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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonalPaths {
    pub socket_dir: PathBuf,
    pub config: PathBuf,
    pub state_dir: PathBuf,
    pub audit_dir: PathBuf,
}

const NO_RUNTIME: &str = "XDG_RUNTIME_DIR is not set or not absolute; log in through a session manager or run as a systemd --user unit";

fn abs_var(env: &dyn Fn(&str) -> Option<OsString>, name: &str) -> Option<PathBuf> {
    let p = PathBuf::from(env(name)?);
    p.is_absolute().then_some(p)
}

pub fn personal_paths(
    env: &dyn Fn(&str) -> Option<OsString>,
    home: Option<&Path>,
) -> Result<PersonalPaths, String> {
    let runtime = abs_var(env, "XDG_RUNTIME_DIR").ok_or_else(|| NO_RUNTIME.to_string())?;
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
        socket_dir: runtime.join("saiife"),
        config: config.join("saiife/broker/config.toml"),
        state_dir: state.join("saiife/broker"),
        audit_dir: data.join("saiife/broker/audit"),
    })
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

    #[test]
    fn runtime_dir_table() {
        let none = envf(HashMap::new());
        assert_eq!(
            personal_paths(&none, Some(Path::new("/h"))).unwrap_err(),
            NO_RUNTIME
        );
        let rel = envf(HashMap::from([("XDG_RUNTIME_DIR", "run".into())]));
        assert_eq!(
            personal_paths(&rel, Some(Path::new("/h"))).unwrap_err(),
            NO_RUNTIME
        );

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
