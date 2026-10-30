//! Personal broker paths (plan 16, decision 2).
//!
//! - sockets: `$XDG_RUNTIME_DIR/saiife/`
//! - config: `$XDG_CONFIG_HOME/saiife/broker/config.toml`
//! - state: `$XDG_STATE_HOME/saiife/broker/`
//! - audit: `$XDG_DATA_HOME/saiife/broker/audit/`
//!
//! XDG fallbacks follow the XDG spec; relative values are ignored.

use std::ffi::OsString;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::layout::Platform;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonalPaths {
    pub socket_dir: PathBuf,
    pub config: PathBuf,
    pub state_dir: PathBuf,
    pub audit_dir: PathBuf,
}

const NO_RUNTIME: &str = "XDG_RUNTIME_DIR is not set or not absolute; log in through a session manager or run as a systemd --user unit";

const NO_RUNTIME_MACOS: &str =
    "there is no home directory to put the personal broker's runtime dir in; set XDG_RUNTIME_DIR";

fn abs_var(env: &dyn Fn(&str) -> Option<OsString>, name: &str) -> Option<PathBuf> {
    let p = PathBuf::from(env(name)?);
    p.is_absolute().then_some(p)
}

/// macOS has no `XDG_RUNTIME_DIR`: the runtime dir is under the home.
pub const MACOS_RUNTIME_REL: &str = "Library/Caches/saiife";

/// The longest `gateway.sock` path macOS can bind (`sun_path` is 104 bytes
/// with the NUL).
pub const MAX_SOCKET_PATH: usize = 103;

pub fn personal_paths(
    env: &dyn Fn(&str) -> Option<OsString>,
    home: Option<&Path>,
) -> Result<PersonalPaths, String> {
    // `None` on another OS keeps the Linux (XDG) rules.
    personal_paths_for(env, home, Platform::current().unwrap_or(Platform::Linux))
}

pub fn personal_paths_for(
    env: &dyn Fn(&str) -> Option<OsString>,
    home: Option<&Path>,
    platform: Platform,
) -> Result<PersonalPaths, String> {
    let socket_dir = match (abs_var(env, "XDG_RUNTIME_DIR"), platform) {
        (Some(r), _) => r.join("saiife"),
        (None, Platform::Macos) => match home {
            Some(h) if h.is_absolute() => h.join(MACOS_RUNTIME_REL).join("run"),
            _ => return Err(NO_RUNTIME_MACOS.to_string()),
        },
        (None, Platform::Linux) => return Err(NO_RUNTIME.to_string()),
    };
    if platform == Platform::Macos {
        let n = socket_dir.join("gateway.sock").as_os_str().len();
        if n > MAX_SOCKET_PATH {
            return Err(format!(
                "the personal broker's socket path is too long for macOS ({n} bytes); set XDG_RUNTIME_DIR to a shorter dir"
            ));
        }
    }
    let base = |var: &str, fallback: &str| -> Result<PathBuf, String> {
        if let Some(p) = abs_var(env, var) {
            return Ok(p);
        }
        match home {
            Some(h) if h.is_absolute() => Ok(h.join(fallback)),
            _ => Err(format!(
                "{var} is not set or not absolute, and there is no home directory to fall back to"
            )),
        }
    };
    let config = base("XDG_CONFIG_HOME", ".config")?;
    let state = base("XDG_STATE_HOME", ".local/state")?;
    let data = base("XDG_DATA_HOME", ".local/share")?;
    Ok(PersonalPaths {
        socket_dir,
        config: config.join("saiife/broker/config.toml"),
        state_dir: state.join("saiife/broker"),
        audit_dir: data.join("saiife/broker/audit"),
    })
}

/// Create the runtime dir 0700 when it is missing (macOS has no session
/// manager to make one). An existing dir is left for [`check_runtime_dir`].
pub fn ensure_runtime_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    if !dir.is_absolute() || std::fs::symlink_metadata(dir).is_ok() {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))
}

/// The `$XDG_RUNTIME_DIR` dir itself: a real dir (no symlink), owned by
/// `euid`, mode 0700.
pub fn check_runtime_dir(dir: &Path, euid: u32) -> Result<(), String> {
    if !dir.is_absolute() {
        return Err(NO_RUNTIME.to_string());
    }
    let md = std::fs::symlink_metadata(dir)
        .map_err(|e| format!("XDG_RUNTIME_DIR {}: {e}", dir.display()))?;
    if md.file_type().is_symlink() {
        return Err(format!(
            "XDG_RUNTIME_DIR {} is a symlink; refusing to use it",
            dir.display()
        ));
    }
    if !md.is_dir() {
        return Err(format!(
            "XDG_RUNTIME_DIR {} is not a directory",
            dir.display()
        ));
    }
    if md.uid() != euid {
        return Err(format!(
            "XDG_RUNTIME_DIR {} is owned by uid {}, not by you (uid {euid})",
            dir.display(),
            md.uid()
        ));
    }
    let mode = md.permissions().mode() & 0o7777;
    if mode != 0o700 {
        return Err(format!(
            "XDG_RUNTIME_DIR {} has mode {mode:04o}; it must be 0700",
            dir.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn envf(m: HashMap<&'static str, String>) -> impl Fn(&str) -> Option<OsString> {
        move |k| m.get(k).map(OsString::from)
    }

    fn euid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    #[test]
    fn paths_from_xdg_vars() {
        let e = envf(HashMap::from([
            ("XDG_RUNTIME_DIR", "/run/user/1000".into()),
            ("XDG_CONFIG_HOME", "/c".into()),
            ("XDG_STATE_HOME", "/s".into()),
            ("XDG_DATA_HOME", "/d".into()),
        ]));
        let p = personal_paths(&e, None).unwrap();
        assert_eq!(p.socket_dir, Path::new("/run/user/1000/saiife"));
        assert_eq!(p.config, Path::new("/c/saiife/broker/config.toml"));
        assert_eq!(p.state_dir, Path::new("/s/saiife/broker"));
        assert_eq!(p.audit_dir, Path::new("/d/saiife/broker/audit"));
    }

    #[test]
    fn paths_fall_back_to_home() {
        let e = envf(HashMap::from([(
            "XDG_RUNTIME_DIR",
            "/run/user/1000".into(),
        )]));
        let p = personal_paths(&e, Some(Path::new("/home/u"))).unwrap();
        assert_eq!(
            p.config,
            Path::new("/home/u/.config/saiife/broker/config.toml")
        );
        assert_eq!(p.state_dir, Path::new("/home/u/.local/state/saiife/broker"));
        assert_eq!(
            p.audit_dir,
            Path::new("/home/u/.local/share/saiife/broker/audit")
        );
        assert!(personal_paths(&e, None).is_err());
    }

    #[test]
    fn relative_xdg_values_ignored() {
        let e = envf(HashMap::from([
            ("XDG_RUNTIME_DIR", "/run/user/1000".into()),
            ("XDG_CONFIG_HOME", "rel".into()),
            ("XDG_STATE_HOME", "rel".into()),
            ("XDG_DATA_HOME", "".into()),
        ]));
        let p = personal_paths(&e, Some(Path::new("/home/u"))).unwrap();
        assert_eq!(
            p.config,
            Path::new("/home/u/.config/saiife/broker/config.toml")
        );
        assert_eq!(p.state_dir, Path::new("/home/u/.local/state/saiife/broker"));
        assert_eq!(
            p.audit_dir,
            Path::new("/home/u/.local/share/saiife/broker/audit")
        );
    }

    fn lin(m: HashMap<&'static str, String>, home: &str) -> Result<PersonalPaths, String> {
        personal_paths_for(&envf(m), Some(Path::new(home)), Platform::Linux)
    }
    fn mac(m: HashMap<&'static str, String>, home: &str) -> Result<PersonalPaths, String> {
        personal_paths_for(&envf(m), Some(Path::new(home)), Platform::Macos)
    }

    #[test]
    fn macos_paths_without_xdg_runtime() {
        let p = mac(HashMap::new(), "/Users/u").unwrap();
        assert_eq!(
            p.socket_dir,
            Path::new("/Users/u/Library/Caches/saiife/run")
        );
        assert_eq!(
            p.config,
            Path::new("/Users/u/.config/saiife/broker/config.toml")
        );
        assert!(personal_paths_for(&envf(HashMap::new()), None, Platform::Macos).is_err());
    }

    #[test]
    fn macos_xdg_runtime_wins() {
        let p = mac(
            HashMap::from([("XDG_RUNTIME_DIR", "/tmp/r".into())]),
            "/Users/u",
        )
        .unwrap();
        assert_eq!(p.socket_dir, Path::new("/tmp/r/saiife"));
    }

    #[test]
    fn macos_runtime_created_0700() {
        let t = tempfile::tempdir().unwrap();
        let rt = t.path().join("Library/Caches/saiife");
        ensure_runtime_dir(&rt).unwrap();
        assert_eq!(
            std::fs::metadata(&rt).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        check_runtime_dir(&rt, euid()).unwrap();
        // An existing dir is not touched: a loose one is still refused.
        let loose = t.path().join("loose");
        std::fs::create_dir(&loose).unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
        ensure_runtime_dir(&loose).unwrap();
        assert!(check_runtime_dir(&loose, euid()).is_err());
    }

    #[test]
    fn macos_socket_path_too_long_refused() {
        let home = format!("/Users/{}", "a".repeat(70));
        let e = mac(HashMap::new(), &home).unwrap_err();
        assert!(
            e.starts_with("the personal broker's socket path is too long for macOS ("),
            "{e}"
        );
        assert!(e.ends_with("set XDG_RUNTIME_DIR to a shorter dir"), "{e}");
        // The same home is fine on Linux, and a short XDG dir fixes macOS.
        assert!(lin(HashMap::from([("XDG_RUNTIME_DIR", "/run/u".into())]), &home).is_ok());
        assert!(mac(HashMap::from([("XDG_RUNTIME_DIR", "/tmp/r".into())]), &home).is_ok());
    }

    #[test]
    fn linux_paths_unchanged() {
        assert_eq!(lin(HashMap::new(), "/home/u").unwrap_err(), NO_RUNTIME);
        let p = lin(
            HashMap::from([("XDG_RUNTIME_DIR", "/run/user/1000".into())]),
            "/home/u",
        )
        .unwrap();
        assert_eq!(p.socket_dir, Path::new("/run/user/1000/saiife"));
    }

    #[test]
    fn runtime_dir_table() {
        // The Linux rule, whatever the build host (macOS falls back to
        // the home: `macos_paths_without_xdg_runtime` covers it).
        let linux = |e: &dyn Fn(&str) -> Option<OsString>| {
            personal_paths_for(e, Some(Path::new("/h")), Platform::Linux)
        };
        let none = envf(HashMap::new());
        assert_eq!(linux(&none).unwrap_err(), NO_RUNTIME);
        let rel = envf(HashMap::from([("XDG_RUNTIME_DIR", "run".into())]));
        assert_eq!(linux(&rel).unwrap_err(), NO_RUNTIME);

        let t = tempfile::tempdir().unwrap();
        let mk = |name: &str, mode: u32| {
            let d = t.path().join(name);
            std::fs::create_dir(&d).unwrap();
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(mode)).unwrap();
            d
        };
        let good = mk("good", 0o700);
        check_runtime_dir(&good, euid()).unwrap();

        let e = check_runtime_dir(&good, euid() + 1).unwrap_err();
        assert!(e.contains("owned by"), "{e}");

        let loose = mk("loose", 0o755);
        let e = check_runtime_dir(&loose, euid()).unwrap_err();
        assert!(e.contains("0700"), "{e}");

        let link = t.path().join("link");
        std::os::unix::fs::symlink(&good, &link).unwrap();
        let e = check_runtime_dir(&link, euid()).unwrap_err();
        assert!(e.contains("symlink"), "{e}");

        let file = t.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        let e = check_runtime_dir(&file, euid()).unwrap_err();
        assert!(e.contains("not a directory"), "{e}");

        assert!(check_runtime_dir(&t.path().join("missing"), euid()).is_err());
        assert!(check_runtime_dir(Path::new("rel"), euid()).is_err());
    }
}
