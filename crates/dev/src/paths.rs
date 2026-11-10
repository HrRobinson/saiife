//! Where saiife dev keeps its state and config. Nothing is created here.
use crate::DevError;
use std::ffi::OsString;
use std::path::PathBuf;

/// The two roots: `state` (generated files) and `config` (user quirks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevPaths {
    pub state: PathBuf,
    pub config: PathBuf,
}

fn absolute(env: &dyn Fn(&str) -> Option<OsString>, key: &str) -> Option<PathBuf> {
    env(key).map(PathBuf::from).filter(|p| p.is_absolute())
}

impl DevPaths {
    pub fn from_env() -> Result<DevPaths, DevError> {
        DevPaths::from_env_with(&|k| std::env::var_os(k))
    }

    pub fn from_env_with(env: &dyn Fn(&str) -> Option<OsString>) -> Result<DevPaths, DevError> {
        let home = || -> Result<PathBuf, DevError> {
            env("HOME")
                .or_else(|| env("USERPROFILE"))
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .ok_or(DevError::NoHome)
        };
        let state = match absolute(env, "XDG_STATE_HOME") {
            Some(p) => p,
            None => home()?.join(".local").join("state"),
        };
        let config = match absolute(env, "XDG_CONFIG_HOME") {
            Some(p) => p,
            None => home()?.join(".config"),
        };
        Ok(DevPaths {
            state: state.join("saiife").join("dev"),
            config: config.join("saiife").join("dev"),
        })
    }

    pub fn project_dir(&self, p: &str) -> PathBuf {
        self.state.join("projects").join(p)
    }

    pub fn proxy_dir(&self) -> PathBuf {
        self.state.join("proxy")
    }

    pub fn ca_dir(&self) -> PathBuf {
        self.state.join("ca")
    }

    pub fn compose_file(&self, p: &str) -> PathBuf {
        self.project_dir(p).join("compose.json")
    }

    pub fn project_file(&self, p: &str) -> PathBuf {
        self.project_dir(p).join("project.json")
    }

    pub fn quirks_file(&self, p: &str) -> PathBuf {
        self.config.join(format!("{p}.toml"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn paths(pairs: &[(&str, &str)]) -> Result<DevPaths, DevError> {
        let m: HashMap<String, OsString> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), OsString::from(v)))
            .collect();
        DevPaths::from_env_with(&|k| m.get(k).cloned())
    }

    #[cfg(unix)]
    const ROOT: &str = "/h";
    #[cfg(windows)]
    const ROOT: &str = "C:\\h";
    #[cfg(unix)]
    const XS: &str = "/x/state";
    #[cfg(windows)]
    const XS: &str = "C:\\x\\state";
    #[cfg(unix)]
    const XC: &str = "/x/cfg";
    #[cfg(windows)]
    const XC: &str = "C:\\x\\cfg";

    fn dev(base: &str, rest: &[&str]) -> PathBuf {
        let mut p = PathBuf::from(base);
        for r in rest {
            p = p.join(r);
        }
        p.join("saiife").join("dev")
    }

    #[test]
    fn xdg_dirs_win() {
        let p = paths(&[
            ("XDG_STATE_HOME", XS),
            ("XDG_CONFIG_HOME", XC),
            ("HOME", ROOT),
        ])
        .unwrap();
        assert_eq!(p.state, dev(XS, &[]));
        assert_eq!(p.config, dev(XC, &[]));
    }

    #[test]
    fn home_fallback() {
        let p = paths(&[("HOME", ROOT)]).unwrap();
        assert_eq!(p.state, dev(ROOT, &[".local", "state"]));
        assert_eq!(p.config, dev(ROOT, &[".config"]));
    }

    #[test]
    fn relative_xdg_is_ignored() {
        let p = paths(&[("XDG_STATE_HOME", "rel"), ("HOME", ROOT)]).unwrap();
        assert_eq!(p.state, dev(ROOT, &[".local", "state"]));
    }

    #[test]
    fn no_home_is_an_error() {
        assert!(matches!(paths(&[]), Err(DevError::NoHome)));
        assert!(matches!(paths(&[("HOME", "rel")]), Err(DevError::NoHome)));
    }

    #[test]
    fn file_names() {
        let p = paths(&[("HOME", ROOT)]).unwrap();
        let proj = p.state.join("projects").join("shop");
        assert_eq!(p.project_dir("shop"), proj);
        assert_eq!(p.compose_file("shop"), proj.join("compose.json"));
        assert_eq!(p.project_file("shop"), proj.join("project.json"));
        assert_eq!(p.quirks_file("shop"), p.config.join("shop.toml"));
        assert_eq!(p.proxy_dir(), p.state.join("proxy"));
        assert_eq!(p.ca_dir(), p.state.join("ca"));
    }
}
