//! Which daemon the CLI talks to (plan 16, decision 10): the locked-mode
//! system daemon or the personal broker (`saiife daemon --user`).
//!
//! A locked host always wins. A `--system-config` flag means locked mode,
//! as before. Without one, `/etc/saiife/config.toml` with `locked = true`
//! means locked mode too; a system config that cannot be read, or a locked
//! install whose config is not locked, is an error, never the broker. Only
//! a host without a locked config uses the personal broker, as the user's
//! own uid. The personal broker is **not a security boundary**.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Instant;

use saiife_ipc::client::{system_uid, Client, ClientError};

/// The broker not running (or its socket gone).
const START_IT: &str = "start it with saiife daemon --user (docs/personal-broker.md)";

/// Where the CLI's control calls go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Target {
    /// The locked-mode daemon, as `[daemon] user` of the system config.
    Locked {
        config: PathBuf,
        socket_dir: PathBuf,
        owner_uid: u32,
    },
    /// The personal broker, as the user's own uid.
    Personal {
        config: PathBuf,
        socket_dir: PathBuf,
        owner_uid: u32,
    },
}

impl Target {
    pub(crate) fn is_locked(&self) -> bool {
        matches!(self, Target::Locked { .. })
    }

    /// The config the daemon serves (the system config, or the broker's).
    pub(crate) fn config(&self) -> &Path {
        match self {
            Target::Locked { config, .. } | Target::Personal { config, .. } => config,
        }
    }
}

/// The target for this command: a flag is locked mode; else
/// `system_config` with `locked = true` is; else the personal broker.
pub(crate) fn resolve(
    config_flag: Option<&Path>,
    system_config: &Path,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<Target, String> {
    if let Some(flag) = config_flag {
        return locked(flag);
    }
    // Read as a raw table (as `saiife audit` does): any failure other than
    // "does not exist" is an error, so a locked host never falls back.
    if crate::audit_locked::locked_audit_dir(system_config)?.is_some() {
        return locked(system_config);
    }
    // Only a marker that is certainly absent lets the broker in: any other
    // failure to look (permission, I/O) is an error.
    let marker = system_config.with_file_name("installed.toml");
    if installed(&marker)? {
        return Err(format!(
            "locked mode is installed ({}) but {} does not say locked = true; the personal broker is not used on a locked host",
            marker.display(),
            system_config.display()
        ));
    }
    personal(env)
}

/// Whether the locked-install marker exists: `false` only when it is
/// certainly absent (`NotFound`); any other failure to look is an error.
fn installed(marker: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(marker) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!(
            "cannot tell whether locked mode is installed ({}): {e}",
            marker.display()
        )),
    }
}

/// The locked-mode target of `config`, which must say `locked = true`
/// and name a daemon user that exists.
pub(crate) fn locked(config: &Path) -> Result<Target, String> {
    let loaded = saiife_policy::load_system(config)
        .map_err(|e| format!("cannot read the system config {}: {e}", config.display()))?;
    if !loaded.config.locked {
        return Err(format!("{}: locked is not true", config.display()));
    }
    let user = &loaded.config.daemon.user;
    let owner_uid =
        system_uid(user).ok_or_else(|| format!("the daemon user {user} does not exist"))?;
    Ok(Target::Locked {
        config: config.to_path_buf(),
        socket_dir: loaded.config.daemon.socket_dir,
        owner_uid,
    })
}

/// The personal broker's target from the environment (the XDG paths).
pub(crate) fn personal(env: &dyn Fn(&str) -> Option<OsString>) -> Result<Target, String> {
    let home = env("HOME").map(PathBuf::from);
    let p = saiife_system::personal::personal_paths(env, home.as_deref())?;
    Ok(Target::Personal {
        config: p.config,
        socket_dir: p.socket_dir,
        owner_uid: rustix::process::getuid().as_raw(),
    })
}

fn owner_err(path: &Path, detail: impl Into<String>) -> ClientError {
    ClientError::Owner {
        path: path.to_path_buf(),
        detail: detail.into(),
    }
}

/// `c` when its hello says `mode = want`; else `Protocol(why)`.
fn hello_mode(c: Client, want: &str, why: &str) -> Result<Client, ClientError> {
    match c.hello_answer().get("mode").and_then(|m| m.as_str()) {
        Some(m) if m == want => Ok(c),
        _ => Err(ClientError::Protocol(why.into())),
    }
}

/// A connection to the target. The hello must say the target's mode
/// (`locked` or `personal`). For the personal broker the runtime dir and
/// the socket dir must be the user's own (never root's or another uid's),
/// and the socket and the peer must be the user's uid.
pub(crate) fn connect(t: &Target, deadline: Instant) -> Result<Client, ClientError> {
    match t {
        Target::Locked {
            socket_dir,
            owner_uid,
            ..
        } => hello_mode(
            Client::connect(socket_dir, *owner_uid, deadline)?,
            "locked",
            "not the locked-mode daemon",
        ),
        Target::Personal {
            socket_dir,
            owner_uid,
            ..
        } => {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if let Some(runtime) = socket_dir.parent() {
                saiife_system::personal::check_runtime_dir(runtime, *owner_uid)
                    .map_err(|e| owner_err(runtime, e))?;
            }
            let md = match std::fs::symlink_metadata(socket_dir) {
                Ok(m) => m,
                Err(e) => return Err(ClientError::Connect(e)),
            };
            if !md.file_type().is_dir() {
                return Err(owner_err(socket_dir, "not a directory"));
            }
            if md.uid() != *owner_uid {
                return Err(owner_err(
                    socket_dir,
                    format!("owned by uid {}, expected {owner_uid}", md.uid()),
                ));
            }
            if md.permissions().mode() & 0o077 != 0 {
                return Err(owner_err(socket_dir, "open to group or others"));
            }
            let sock = socket_dir.join(saiife_ipc::msg::SOCKET_NAME);
            if let Err(e) = std::fs::symlink_metadata(&sock) {
                return Err(ClientError::Connect(e));
            }
            hello_mode(
                Client::connect(socket_dir, *owner_uid, deadline)?,
                "personal",
                "not a personal broker",
            )
        }
    }
}

/// The line for a connection (or call) that failed with `e`.
pub(crate) fn unreachable(t: &Target, e: &ClientError) -> String {
    match t {
        Target::Locked { .. } => format!("cannot reach the saiife daemon: {e}"),
        Target::Personal { socket_dir, .. } => match e {
            ClientError::Connect(_) => format!(
                "cannot reach the personal broker at {}: {START_IT}",
                socket_dir.display()
            ),
            other => format!("personal broker at {}: {other}", socket_dir.display()),
        },
    }
}

/// The resolver for this process: the real `/etc/saiife/config.toml` and
/// environment.
pub(crate) fn resolve_here(config_flag: Option<&Path>) -> Result<Target, String> {
    resolve(config_flag, &system_config(), &|k| std::env::var_os(k))
}

/// `/etc/saiife/config.toml`; debug builds take `SAIIFE_TEST_SYSTEM_CONFIG`
/// (an absolute path), so a test never depends on the host's config.
#[cfg(debug_assertions)]
fn system_config() -> PathBuf {
    std::env::var_os("SAIIFE_TEST_SYSTEM_CONFIG")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| PathBuf::from(crate::audit_locked::SYSTEM_CONFIG))
}

#[cfg(not(debug_assertions))]
fn system_config() -> PathBuf {
    PathBuf::from(crate::audit_locked::SYSTEM_CONFIG)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;

    fn own_uid() -> u32 {
        rustix::process::getuid().as_raw()
    }

    fn own_user() -> String {
        saiife_ipc::client::system_entry(own_uid()).unwrap().name
    }

    fn envf(m: HashMap<&'static str, PathBuf>) -> impl Fn(&str) -> Option<OsString> {
        move |k| m.get(k).map(|p| p.clone().into_os_string())
    }

    struct World {
        _tmp: tempfile::TempDir,
        root: PathBuf,
    }

    impl World {
        fn new() -> World {
            let base = std::env::var_os("SAIIFE_TEST_TMP")
                .or_else(|| std::env::var_os("TMPDIR"))
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir);
            let tmp = tempfile::Builder::new()
                .prefix("bk")
                .tempdir_in(base)
                .unwrap();
            let root = tmp.path().to_path_buf();
            World { _tmp: tmp, root }
        }
        fn etc(&self) -> PathBuf {
            let d = self.root.join("etc");
            fs::create_dir_all(&d).unwrap();
            d.join("config.toml")
        }
        fn env(&self) -> impl Fn(&str) -> Option<OsString> {
            envf(HashMap::from([
                ("XDG_RUNTIME_DIR", self.root.join("r")),
                ("XDG_CONFIG_HOME", self.root.join("c")),
                ("XDG_STATE_HOME", self.root.join("s")),
                ("XDG_DATA_HOME", self.root.join("d")),
                ("HOME", self.root.join("h")),
            ]))
        }
        fn locked_text(&self, user: &str) -> String {
            format!(
                "version = 2\nlocked = true\n\n[daemon]\nuser = {user:?}\nsocket_dir = {:?}\n",
                self.root.join("run").display().to_string()
            )
        }
        fn personal(&self) -> Target {
            Target::Personal {
                config: self.root.join("c/saiife/broker/config.toml"),
                socket_dir: self.root.join("r/saiife"),
                owner_uid: own_uid(),
            }
        }
    }

    #[test]
    fn locked_host_wins() {
        let w = World::new();
        let etc = w.etc();
        fs::write(&etc, w.locked_text(&own_user())).unwrap();
        // A personal broker's dir exists too; the locked daemon still wins.
        fs::create_dir_all(w.root.join("r/saiife")).unwrap();
        let t = resolve(None, &etc, &w.env()).unwrap();
        assert!(t.is_locked());
        assert_eq!(
            t,
            Target::Locked {
                config: etc.clone(),
                socket_dir: w.root.join("run"),
                owner_uid: own_uid(),
            }
        );
        assert_eq!(t.config(), etc);
        // A locked config whose daemon user is missing is an error, never
        // the broker.
        fs::write(&etc, w.locked_text("saiife-no-such-user-x")).unwrap();
        let e = resolve(None, &etc, &w.env()).unwrap_err();
        assert!(e.contains("does not exist"), "{e}");
        // So is a locked config that does not load.
        fs::write(&etc, "version = 3\nlocked = true\n").unwrap();
        assert!(resolve(None, &etc, &w.env()).is_err());
        // And one that is not even TOML.
        fs::write(&etc, "locked = [").unwrap();
        assert!(resolve(None, &etc, &w.env()).is_err());
        // A locked install (the marker) whose config is not locked.
        fs::write(&etc, "version = 2\n").unwrap();
        fs::write(etc.with_file_name("installed.toml"), "").unwrap();
        let e = resolve(None, &etc, &w.env()).unwrap_err();
        assert!(e.contains("locked mode is installed"), "{e}");
        // A marker that cannot be looked at (not NotFound) refuses too.
        let odd = w.root.join("file-not-dir");
        fs::write(&odd, "").unwrap();
        let e = installed(&odd.join("installed.toml")).unwrap_err();
        assert!(
            e.contains("cannot tell whether locked mode is installed"),
            "{e}"
        );
        assert_eq!(installed(&w.root.join("absent.toml")), Ok(false));
    }

    #[test]
    fn flag_is_locked() {
        let w = World::new();
        let cfg = w.root.join("flag.toml");
        fs::write(&cfg, w.locked_text(&own_user())).unwrap();
        // The system config is absent: the flag alone decides.
        let t = resolve(Some(&cfg), &w.root.join("absent.toml"), &w.env()).unwrap();
        assert!(t.is_locked());
        assert_eq!(t.config(), cfg);
        // A flag never falls back to the broker.
        fs::write(&cfg, "version = 2\n").unwrap();
        let e = resolve(Some(&cfg), &w.root.join("absent.toml"), &w.env()).unwrap_err();
        assert!(e.ends_with("locked is not true"), "{e}");
        let e = resolve(
            Some(&w.root.join("nope.toml")),
            &w.root.join("absent.toml"),
            &w.env(),
        )
        .unwrap_err();
        let want = format!(
            "cannot read the system config {}:",
            w.root.join("nope.toml").display()
        );
        assert!(e.starts_with(&want), "{e}");
    }

    #[test]
    fn no_locked_config_is_personal() {
        let w = World::new();
        let t = resolve(None, &w.root.join("etc/config.toml"), &w.env()).unwrap();
        assert!(!t.is_locked());
        assert_eq!(t, w.personal());
        // No XDG_RUNTIME_DIR: an error naming it, never a fallback.
        let none = |_: &str| None;
        let e = resolve(None, &w.root.join("etc/config.toml"), &none).unwrap_err();
        assert!(e.contains("XDG_RUNTIME_DIR"), "{e}");
    }

    #[test]
    fn unlocked_system_config_is_personal() {
        let w = World::new();
        let etc = w.etc();
        fs::write(&etc, "version = 2\nlocked = false\n").unwrap();
        assert_eq!(resolve(None, &etc, &w.env()).unwrap(), w.personal());
        // A developer-mode config that is not valid policy is not locked
        // either.
        fs::write(&etc, "version = 2\n[guard]\npacks = 3\n").unwrap();
        assert_eq!(resolve(None, &etc, &w.env()).unwrap(), w.personal());
    }

    #[test]
    fn personal_connect_refuses_foreign_or_open_dirs() {
        use std::os::unix::fs::PermissionsExt;
        let w = World::new();
        let rt = w.root.join("r");
        fs::create_dir(&rt).unwrap();
        fs::set_permissions(&rt, fs::Permissions::from_mode(0o700)).unwrap();
        let t = w.personal();
        let dl = Instant::now() + std::time::Duration::from_secs(1);
        // No broker: the start-it line.
        let e = connect(&t, dl).unwrap_err();
        assert!(matches!(e, ClientError::Connect(_)), "{e:?}");
        assert_eq!(
            unreachable(&t, &e),
            format!(
                "cannot reach the personal broker at {}: start it with saiife daemon --user (docs/personal-broker.md)",
                rt.join("saiife").display()
            )
        );
        // A socket dir open to others is refused before any connect.
        fs::create_dir(rt.join("saiife")).unwrap();
        fs::set_permissions(rt.join("saiife"), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(connect(&t, dl), Err(ClientError::Owner { .. })));
        // A runtime dir open to others is refused too.
        fs::set_permissions(rt.join("saiife"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&rt, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(connect(&t, dl), Err(ClientError::Owner { .. })));
        // A broker of another uid: the dir check names the owner.
        fs::set_permissions(&rt, fs::Permissions::from_mode(0o700)).unwrap();
        let other = Target::Personal {
            config: PathBuf::new(),
            socket_dir: rt.join("saiife"),
            owner_uid: own_uid() + 1,
        };
        assert!(matches!(
            connect(&other, dl),
            Err(ClientError::Owner { .. })
        ));
    }
}
