//! Which systems locked mode supports (spec §0 decision 8): Ubuntu 22.04+,
//! Debian 12+, RHEL 9+ (and distributions `ID_LIKE` rhel, 9+), each with
//! systemd running, macOS 15 or later (plan 13 decision 13), and Windows 11 23H2 or
//! Server 2022 or later (plan 19b). Alpine and containers get developer mode only.

use crate::host::{Host, CONTAINER_UNKNOWN, REG_NT_CURRENT_VERSION};
use crate::layout::{Layout, Platform};
use std::collections::BTreeMap;

/// The reason on any other OS.
pub const NOT_SUPPORTED_OS: &str = "locked mode needs Linux, macOS or Windows";

/// The oldest client locked mode supports: Windows 11 23H2.
pub const MIN_WIN_CLIENT_BUILD: u32 = 22631;
/// The oldest server locked mode supports: Server 2022.
pub const MIN_WIN_SERVER_BUILD: u32 = 20348;

/// The key of `ProgramFilesDir`, below HKLM.
pub const REG_CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion";
/// The key of `ProgramData`, below HKLM. The value is `REG_EXPAND_SZ`, stored as
/// `%SystemDrive%\ProgramData`.
pub const REG_PROFILE_LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
/// The key of the `ContainerType` value, below HKLM.
pub const REG_CONTROL: &str = r"SYSTEM\CurrentControlSet\Control";

/// W9's refusal.
pub const NON_DEFAULT_FOLDERS: &str =
    "non-default system folders are not supported in this version";
/// W26's refusal.
pub const NOT_ELEVATED: &str = "run this from an elevated terminal (Run as administrator)";

/// The oldest macOS locked mode supports (Sequoia, plan 13 decision 13).
pub const MIN_MACOS: (u32, u32) = (15, 0);

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

/// Checks this machine (or the tree under `layout`'s root) by the
/// layout's platform. On Linux: a container, systemd and its version, then
/// the distribution from `<root>/etc/os-release`. On macOS: the version
/// `sw_vers` reports. On Windows: a container, the build and the system folders. Whether
/// the caller is elevated is no fact about the machine: see W26 in
/// `install_win::host_refusals`. Any other OS is refused.
pub fn check_supported(layout: &Layout, host: &dyn Host) -> Support {
    supported_on(Platform::current(), layout, host)
}

/// [`check_supported`] with the running OS given (`None`: none of the three).
pub(crate) fn supported_on(current: Option<Platform>, layout: &Layout, host: &dyn Host) -> Support {
    if current.is_none() {
        return Support::Refused(NOT_SUPPORTED_OS.to_string());
    }
    match layout.platform() {
        Platform::Linux => linux_supported(layout, host),
        Platform::Windows => windows_supported(host),
        Platform::Macos => macos_supported(host),
    }
}

/// A Windows container: `ContainerType` is present, whatever its type. A failed read
/// is an `Err`, never "no container", so callers fail closed as on Linux.
pub(crate) fn windows_container(host: &dyn Host) -> std::io::Result<bool> {
    host.reg_value_present(REG_CONTROL, "ContainerType")
}

/// W9: the registry says `C:\Windows`, `C:\Program Files` and `C:\ProgramData`. Never
/// read from environment variables, which the caller controls. `ProgramData` is stored
/// as `%SystemDrive%\ProgramData`, and `SystemRoot` says that drive is `C:`.
///
/// `SystemRoot` counts on its own too: install runs `C:\Windows\System32\net.exe` and
/// `sc.exe`. With Windows on another drive, that folder would be unmade, and
/// Authenticated Users may create entries in `C:\`.
pub(crate) fn default_folders(host: &dyn Host) -> bool {
    let is = |got: Option<String>, want: &str| got.is_some_and(|g| g.eq_ignore_ascii_case(want));
    let data = host.reg_string(REG_PROFILE_LIST, "ProgramData");
    is(
        host.reg_string(REG_NT_CURRENT_VERSION, "SystemRoot"),
        r"C:\Windows",
    ) && is(
        host.reg_string(REG_CURRENT_VERSION, "ProgramFilesDir"),
        r"C:\Program Files",
    ) && (is(data.clone(), r"C:\ProgramData") || is(data, r"%SystemDrive%\ProgramData"))
}

/// The checks of [`check_supported`] on Windows, in that order. `systemd` is 0.
fn windows_supported(host: &dyn Host) -> Support {
    match windows_container(host) {
        Ok(false) => {}
        Ok(true) => {
            return Support::Refused("inside a Windows container: developer mode only".into())
        }
        Err(e) => {
            return Support::Refused(format!(
                "container detection failed (the registry's ContainerType could not be \
                 read: {e}); locked mode needs it to rule out a container"
            ))
        }
    }
    let build = match host.windows_build() {
        Ok(b) => b,
        Err(e) => return Support::Refused(format!("the Windows build could not be read: {e}")),
    };
    let min = if build.server {
        MIN_WIN_SERVER_BUILD
    } else {
        MIN_WIN_CLIENT_BUILD
    };
    if build.build < min {
        return Support::Refused(format!(
            "Windows build {} is not supported for locked mode \
             (Windows 11 23H2 / Server 2022 or later)",
            build.build
        ));
    }
    if !default_folders(host) {
        return Support::Refused(NON_DEFAULT_FOLDERS.to_string());
    }
    Support::Supported {
        distro: format!(
            "Windows {} build {}",
            if build.server { "Server" } else { "client" },
            build.build
        ),
        systemd: 0,
    }
}

/// macOS [`MIN_MACOS`] or later. There is no systemd: `systemd` is 0.
fn macos_supported(host: &dyn Host) -> Support {
    let (major, minor) = match host.macos_version() {
        Ok(v) => v,
        Err(e) => return Support::Refused(format!("the macOS version could not be read: {e}")),
    };
    if (major, minor) < MIN_MACOS {
        return Support::Refused(format!(
            "macOS {major}.{minor} is not supported for locked mode (macOS {} or later)",
            MIN_MACOS.0
        ));
    }
    Support::Supported {
        distro: format!("macOS {major}.{minor}"),
        systemd: 0,
    }
}

fn linux_supported(layout: &Layout, host: &dyn Host) -> Support {
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

/// Pure, on every OS: the fake host stands in for Windows.
#[cfg(test)]
mod windows_tests {
    use super::*;
    use crate::host::{FakeHost, RegValue, WinBuild};

    /// A stock, elevated machine reporting `build`.
    fn machine(build: u32, server: bool) -> (tempfile::TempDir, Layout, FakeHost) {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::under_for(dir.path(), Platform::Windows);
        let host = FakeHost::open(dir.path()).unwrap();
        host.set(|s| {
            s.build = WinBuild { build, server };
            s.euid = 0;
        });
        (dir, layout, host)
    }

    fn check(l: &Layout, h: &FakeHost) -> Support {
        supported_on(Some(Platform::Windows), l, h)
    }

    fn refused(s: Support) -> String {
        match s {
            Support::Refused(why) => why,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    fn set_str(h: &FakeHost, key: &str, value: &str, v: &str) {
        let k = (key.to_string(), value.to_string());
        h.set(|s| {
            s.registry.insert(k, RegValue::Str(v.to_string()));
        });
    }

    #[test]
    fn windows_supported_from_22631() {
        assert_eq!(MIN_WIN_CLIENT_BUILD, 22631);
        let (_d, l, h) = machine(22631, false);
        assert_eq!(
            check(&l, &h),
            Support::Supported {
                distro: "Windows client build 22631".into(),
                systemd: 0
            }
        );
        let (_d, l, h) = machine(26100, false);
        assert!(matches!(check(&l, &h), Support::Supported { .. }));
        let (_d, l, h) = machine(22621, false);
        assert!(refused(check(&l, &h)).starts_with("Windows build 22621 is not supported"));
    }

    #[test]
    fn windows_19045_refused() {
        let (_d, l, h) = machine(19045, false);
        assert_eq!(
            refused(check(&l, &h)),
            "Windows build 19045 is not supported for locked mode \
             (Windows 11 23H2 / Server 2022 or later)"
        );
    }

    /// The server floor is lower than the client's, and a client does not get it.
    #[test]
    fn server_2022_supported() {
        assert_eq!(MIN_WIN_SERVER_BUILD, 20348);
        let (_d, l, h) = machine(20348, true);
        assert_eq!(
            check(&l, &h),
            Support::Supported {
                distro: "Windows Server build 20348".into(),
                systemd: 0
            }
        );
        let (_d, l, h) = machine(20347, true);
        assert!(refused(check(&l, &h)).starts_with("Windows build 20347 is not supported"));
        let (_d, l, h) = machine(20348, false);
        assert!(refused(check(&l, &h)).starts_with("Windows build 20348 is not supported"));
    }

    #[test]
    fn container_refused() {
        let (_d, l, h) = machine(26100, true);
        let k = (REG_CONTROL.to_string(), "ContainerType".to_string());
        h.set(|s| {
            s.registry.insert(k.clone(), RegValue::Dword(2));
        });
        let why = refused(check(&l, &h));
        assert_eq!(why, "inside a Windows container: developer mode only");
        // Of whichever type, and before anything else is asked.
        h.set(|s| {
            s.registry.insert(k, RegValue::Str("x".into()));
            s.build.build = 1;
            s.euid = 1000;
        });
        assert_eq!(refused(check(&l, &h)), why);
    }

    #[test]
    fn non_default_program_files_refused() {
        let (_d, l, h) = machine(26100, true);
        set_str(
            &h,
            REG_CURRENT_VERSION,
            "ProgramFilesDir",
            r"D:\Program Files",
        );
        assert_eq!(
            refused(check(&l, &h)),
            "non-default system folders are not supported in this version"
        );

        // Missing is no default either: fail closed.
        let (_d, l, h) = machine(26100, true);
        h.set(|s| {
            s.registry.clear();
        });
        assert_eq!(refused(check(&l, &h)), NON_DEFAULT_FOLDERS);
    }

    #[test]
    fn program_data_is_read_as_the_registry_stores_it() {
        // The stock value holds the variable, on a C: system drive.
        let (_d, l, h) = machine(26100, true);
        assert!(matches!(check(&l, &h), Support::Supported { .. }));
        for (data, ok) in [
            (r"C:\ProgramData", true),
            (r"c:\programdata", true),
            (r"%SYSTEMDRIVE%\ProgramData", true),
            (r"D:\ProgramData", false),
            (r"%SystemDrive%\Data", false),
            (r"%ProgramData%", false),
        ] {
            set_str(&h, REG_PROFILE_LIST, "ProgramData", data);
            assert_eq!(default_folders(&h), ok, "{data}");
        }
        // The variable means another drive when Windows lives on one.
        set_str(
            &h,
            REG_PROFILE_LIST,
            "ProgramData",
            r"%SystemDrive%\ProgramData",
        );
        set_str(&h, REG_NT_CURRENT_VERSION, "SystemRoot", r"D:\Windows");
        assert!(!default_folders(&h));
    }

    /// Windows on D: with both folder values on C: leaves `C:\Windows` unmade, and
    /// Authenticated Users can create entries in `C:\`. They could plant
    /// `C:\Windows\System32\net.exe`, which an elevated install then runs. So the
    /// tools' own folder is checked whatever the other two say.
    #[test]
    fn windows_elsewhere_refused_whatever_the_folders_say() {
        let (_d, l, h) = machine(26100, true);
        set_str(&h, REG_PROFILE_LIST, "ProgramData", r"C:\ProgramData");
        assert!(default_folders(&h));
        set_str(&h, REG_NT_CURRENT_VERSION, "SystemRoot", r"C:\WINDOWS");
        assert!(default_folders(&h), "the case does not matter");

        set_str(&h, REG_NT_CURRENT_VERSION, "SystemRoot", r"D:\Windows");
        assert!(!default_folders(&h));
        assert_eq!(refused(check(&l, &h)), NON_DEFAULT_FOLDERS);

        h.set(|s| {
            s.registry
                .remove(&(REG_NT_CURRENT_VERSION.to_string(), "SystemRoot".to_string()));
        });
        assert!(!default_folders(&h), "a missing SystemRoot is no default");
    }

    /// Present is present: the value's type does not matter.
    #[test]
    fn container_value_of_any_type_refused() {
        let k = (REG_CONTROL.to_string(), "ContainerType".to_string());
        for value in [
            RegValue::Dword(2),
            RegValue::Str("x".into()),
            RegValue::Other,
        ] {
            let (_d, l, h) = machine(26100, true);
            h.set(|s| {
                s.registry.insert(k.clone(), value.clone());
            });
            assert_eq!(
                refused(check(&l, &h)),
                "inside a Windows container: developer mode only",
                "{value:?}"
            );
        }
    }

    /// Only "not found" means no container, as on Linux (`unknown_container_refused`).
    #[test]
    fn container_probe_failure_refused() {
        let (_d, l, h) = machine(26100, true);
        h.set(|s| s.reg_probe_error = Some("Access is denied.".into()));
        let why = refused(check(&l, &h));
        assert!(why.starts_with("container detection failed"), "{why}");
        assert!(why.contains("Access is denied."), "{why}");
        assert!(!why.starts_with("inside a"), "{why}");
    }

    /// W26 is about the caller, not the machine: doctor from a plain shell must still say
    /// this machine is supported. Install refuses, in `install_win::host_refusals`.
    #[test]
    fn a_plain_token_does_not_make_the_machine_unsupported() {
        let (_d, l, h) = machine(26100, true);
        h.set(|s| s.euid = 0x4000_1234);
        assert!(matches!(check(&l, &h), Support::Supported { .. }));
    }

    #[test]
    fn unreadable_build_refused() {
        assert!(crate::host::parse_win_build(None, None).is_err());
    }

    #[test]
    fn other_os_refused_with_the_new_text() {
        let (_d, l, h) = machine(26100, true);
        assert_eq!(
            refused(supported_on(None, &l, &h)),
            "locked mode needs Linux, macOS or Windows"
        );
    }
}

#[cfg(all(test, unix))]
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
        let layout = Layout::under_for(dir.path(), Platform::Linux);
        let host = FakeHost::open(dir.path()).unwrap();
        (dir, layout, host)
    }

    /// The check as it runs on Linux, so these tests also run on macOS.
    fn check_linux(l: &Layout, h: &FakeHost) -> Support {
        supported_on(Some(Platform::Linux), l, h)
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
            refused(supported_on(None, &l, &h)),
            "locked mode needs Linux, macOS or Windows"
        );
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        assert_eq!(refused(check_supported(&l, &h)), NOT_SUPPORTED_OS);
    }

    /// A macOS tree and its host, reporting `version` from `sw_vers`.
    fn macos_with(version: (u32, u32)) -> (tempfile::TempDir, Layout, FakeHost) {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::under_for(dir.path(), Platform::Macos);
        let host = FakeHost::open(dir.path()).unwrap();
        host.set(|s| s.macos = version);
        (dir, layout, host)
    }

    #[test]
    fn macos_supported_from_15() {
        assert_eq!(MIN_MACOS, (15, 0));
        let (_d, l, h) = macos_with((15, 0));
        assert_eq!(
            supported_on(Some(Platform::Macos), &l, &h),
            Support::Supported {
                distro: "macOS 15.0".into(),
                systemd: 0
            }
        );
        for v in [(15, 1), (15, 7), (26, 0)] {
            h.set(|s| s.macos = v);
            assert!(matches!(
                supported_on(Some(Platform::Macos), &l, &h),
                Support::Supported { systemd: 0, .. }
            ));
        }
        // The layout's platform decides, not the OS the tests run on.
        assert!(matches!(
            supported_on(Some(Platform::Linux), &l, &h),
            Support::Supported { .. }
        ));
        // The default fake reports 15.0.
        let dir = tempfile::tempdir().unwrap();
        let h = FakeHost::open(dir.path()).unwrap();
        assert_eq!(h.macos_version().unwrap(), (15, 0));
    }

    #[test]
    fn macos_14_refused() {
        let (_d, l, h) = macos_with((14, 6));
        assert_eq!(
            refused(supported_on(Some(Platform::Macos), &l, &h)),
            "macOS 14.6 is not supported for locked mode (macOS 15 or later)"
        );
        // A container or a missing systemd is not asked about on macOS.
        h.set(|s| {
            s.macos = (15, 0);
            s.container = Some("docker".into());
        });
        assert!(matches!(
            supported_on(Some(Platform::Macos), &l, &h),
            Support::Supported { .. }
        ));
        // An unsupported OS is refused before the platform is looked at.
        assert_eq!(refused(supported_on(None, &l, &h)), NOT_SUPPORTED_OS);
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
