//! The directories the guard's path rules are bound to (spec §7.2, §7.4):
//! the working directory relative paths are resolved against, and the
//! values of the rule variables (`~`, `$PROJECT`, `$SAIIFE_DATA_DIR`,
//! `$SAIIFE_AUDIT_DIR`, `$SAIIFE_BIN`, `$CLAUDE_CONFIG_DIR`, `$CODEX_HOME`,
//! and locked mode's system paths `$SAIIFE_ETC`, `$SAIIFE_STATE`,
//! `$SAIIFE_LOG`, `$SAIIFE_RUN`, `$SAIIFE_OPT`, `$SAIIFE_UNIT`).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use saiife_agents::detect::{agent_paths, find_in_path, find_in_path_ext, which};
use saiife_agents::integrity;
use saiife_agents::Agent;
use saiife_audit::store;
use saiife_system::layout::Platform;
use saiifeguard::canon::{PathStyle, PathVars};

/// The system config the developer hook and `saiife audit` read for locked
/// mode (`locked = true`, `[guard] fail`). On Windows it is under ProgramData
/// (plan 19a, W-decisions); no locked install writes it before plan 19b.
#[cfg(unix)]
pub const DEV_SYSTEM_CONFIG: &str = "/etc/saiife/config.toml";
#[cfg(windows)]
pub const DEV_SYSTEM_CONFIG: &str = r"C:\ProgramData\saiife\etc\config.toml";

/// An agent config dir: `value` when set and absolute, else `default` under
/// `home` (`None` when neither is known).
fn config_dir(
    value: Option<std::ffi::OsString>,
    home: Option<PathBuf>,
    default: &str,
) -> Option<PathBuf> {
    match value {
        Some(d) if Path::new(&d).is_absolute() => Some(PathBuf::from(d)),
        _ => home.map(|h| h.join(default)),
    }
}

/// An agent's config dir: `value` when set and absolute, else the default
/// from [`agent_paths`] under `home`.
fn agent_config_dir(
    value: Option<std::ffi::OsString>,
    home: Option<&Path>,
    agent: Agent,
    windows: bool,
) -> Option<PathBuf> {
    match value {
        Some(d) if Path::new(&d).is_absolute() => Some(PathBuf::from(d)),
        _ => agent_paths(home?, windows)
            .of(agent)
            .map(|p| p.config_dir.clone()),
    }
}

/// Locked mode's system paths (spec §5.2), at their defaults; on macOS the
/// §5.3 ones. Always bound: only `core.lock` uses them, and it is on only
/// in locked mode (or when a project turns it on).
const SYSTEM_PATHS: [(&str, &str); 6] = system_paths(if cfg!(target_os = "macos") {
    Platform::Macos
} else if cfg!(windows) {
    Platform::Windows
} else {
    Platform::Linux
});

/// The rule variables of [`SYSTEM_PATHS`] on `p`. The macOS values are
/// `layout::macos_path` of the Linux ones (checked by a test).
const fn system_paths(p: Platform) -> [(&'static str, &'static str); 6] {
    use saiife_system::layout::{ETC_DIR, LOG_DIR, OPT_DIR, RUN_DIR, STATE_DIR, UNIT};
    let (state, run, unit) = match p {
        Platform::Linux => (STATE_DIR, RUN_DIR, UNIT),
        // Spec §5.3a: everything under C:\ProgramData\saiife. Windows has no
        // run dir (the endpoint is a pipe) and no unit file; those two names
        // bind the run dir path and the service binary so `core.lock` still
        // protects what is there.
        Platform::Windows => {
            return [
                ("SAIIFE_ETC", r"C:\ProgramData\saiife\etc"),
                ("SAIIFE_STATE", r"C:\ProgramData\saiife\state"),
                ("SAIIFE_LOG", r"C:\ProgramData\saiife\log"),
                ("SAIIFE_RUN", r"C:\ProgramData\saiife\run"),
                ("SAIIFE_OPT", r"C:\ProgramData\saiife"),
                ("SAIIFE_UNIT", r"C:\ProgramData\saiife\bin\saiife.exe"),
            ];
        }
        Platform::Macos => (
            "/var/db/saiife",
            "/var/db/saiife-run",
            "/Library/LaunchDaemons/com.saiife.saiifed.plist",
        ),
    };
    [
        ("SAIIFE_ETC", ETC_DIR),
        ("SAIIFE_STATE", state),
        ("SAIIFE_LOG", LOG_DIR),
        ("SAIIFE_RUN", run),
        ("SAIIFE_OPT", OPT_DIR),
        ("SAIIFE_UNIT", unit),
    ]
}

/// Where a locked host's system config puts saiife's paths, when they are
/// not the §5.2 defaults: bound as extra values of the rule variables.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct LockedPaths {
    /// The directory holding the system config (`/etc/saiife`).
    pub etc: PathBuf,
    /// `[audit] dir`.
    pub audit_dir: PathBuf,
    /// `[daemon] socket_dir`.
    pub socket_dir: PathBuf,
}

/// The Windows variables a path may be spelled with (W6), bound when set.
const WINDOWS_VARS: [&str; 12] = [
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
    "TEMP",
    "TMP",
    "PROGRAMDATA",
    "ALLUSERSPROFILE",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "COMPUTERNAME",
];

/// `v` in `PathStyle::Windows`, with the variables `env` has a value for.
fn bind_windows_vars(v: PathVars, env: impl Fn(&str) -> Option<std::ffi::OsString>) -> PathVars {
    let v = v.with_style(PathStyle::Windows);
    WINDOWS_VARS.iter().fold(v, |v, name| match env(name) {
        Some(value) => v.with_var(name, value),
        None => v,
    })
}

/// `cwd`: where relative paths start (the hook payload's `cwd`); `project`:
/// the saiife project root, `cwd` if there is none. Every value the
/// process cannot determine is left out, so rules that need it do not apply.
pub fn path_vars(cwd: Option<&Path>, project: Option<&Path>) -> PathVars {
    path_vars_locked(cwd, project, None)
}

/// `path_vars`, plus the paths a locked host's system config names
/// (`locked`) as extra values of `$SAIIFE_ETC`, `$SAIIFE_AUDIT_DIR` and
/// `$SAIIFE_RUN`.
pub fn path_vars_locked(
    cwd: Option<&Path>,
    project: Option<&Path>,
    locked: Option<&LockedPaths>,
) -> PathVars {
    let found = Found {
        home: saiife_win::profile::home_dir(),
        data_dir: integrity::data_dir(),
        audit_dir: store::default_dir(),
        saiife: which("saiife"),
    };
    bind_vars(
        (cwd, project, locked),
        &|name| std::env::var_os(name),
        found,
    )
}

/// An environment as a list, as a worker child is started with it.
pub type EnvList = [(OsString, OsString)];

/// `path_vars_locked` as a process started with exactly `env` binds it, read from `env`
/// alone and never from this process's environment: the locked hook judges Claude Code's
/// calls in its own process (plan 21), and its environment is the agent's. A home or data
/// dir that `env` lacks is left out: no fallback reads this process's environment.
pub fn path_vars_locked_env(
    cwd: Option<&Path>,
    project: Option<&Path>,
    locked: Option<&LockedPaths>,
    env: &EnvList,
) -> PathVars {
    let get = |name: &str| {
        env.iter()
            .rev()
            .find(|(k, _)| match cfg!(windows) {
                true => k.eq_ignore_ascii_case(name),
                false => k == name,
            })
            .map(|(_, v)| v.clone())
    };
    let absolute = |name: &str| {
        get(name)
            .filter(|d| Path::new(d).is_absolute())
            .map(PathBuf::from)
    };
    // As `saiife_win::profile::{home_dir, data_base_dir}`, and `dirs` on Unix.
    #[cfg(windows)]
    let (home, base) = (absolute("USERPROFILE"), absolute("LOCALAPPDATA"));
    #[cfg(not(windows))]
    let home = get("HOME").filter(|h| !h.is_empty()).map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let base = home.as_ref().map(|h| h.join("Library/Application Support"));
    #[cfg(all(unix, not(target_os = "macos")))]
    let base = absolute("XDG_DATA_HOME").or_else(|| home.as_ref().map(|h| h.join(".local/share")));
    // As `integrity::data_dir`, `store::default_dir` and `detect::which`.
    let data = base.map(|b| b.join("saiife"));
    let found = Found {
        data_dir: absolute(integrity::DATA_DIR_ENV).or_else(|| data.clone()),
        audit_dir: absolute(store::DIR_ENV).or_else(|| data.map(|d| d.join("audit"))),
        saiife: get("PATH").and_then(|path| match cfg!(windows) {
            true => {
                let exts = get("PATHEXT").and_then(|e| e.into_string().ok());
                let exts = exts.unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".into());
                find_in_path_ext("saiife", &path, &exts)
            }
            false => find_in_path("saiife", &path),
        }),
        home,
    };
    bind_vars((cwd, project, locked), &get, found)
}

/// What [`bind_vars`] takes from the profile and the file system rather than from one
/// variable: the home, saiife's data and audit dirs, and the `saiife` on `PATH`.
struct Found {
    home: Option<PathBuf>,
    data_dir: Option<PathBuf>,
    audit_dir: Option<PathBuf>,
    saiife: Option<PathBuf>,
}

/// The rule variables, with the agents' variables read through `env`.
fn bind_vars(
    (cwd, project, locked): (Option<&Path>, Option<&Path>, Option<&LockedPaths>),
    env: &dyn Fn(&str) -> Option<OsString>,
    found: Found,
) -> PathVars {
    let mut v = PathVars::new().with_style(PathStyle::host());
    if v.style() == PathStyle::Windows {
        v = bind_windows_vars(v, env);
    }
    if let Some(c) = cwd {
        v = v.with_cwd(c);
    }
    if let Some(h) = &found.home {
        v = v.with_var("HOME", h);
    }
    // The agents' config dirs: the variable when set (and absolute), else
    // the default under HOME, so the rules naming them are always active.
    // `XDG_CONFIG_HOME` the same way (`~/.config`); in locked mode the
    // worker's environment is cleared, so it is always the default there.
    let home = found.home;
    for (name, agent) in [
        ("CLAUDE_CONFIG_DIR", Agent::Claude),
        ("CODEX_HOME", Agent::Codex),
    ] {
        if let Some(d) = agent_config_dir(env(name), home.as_deref(), agent, cfg!(windows)) {
            v = v.with_var(name, d);
        }
    }
    if let Some(d) = config_dir(env("XDG_CONFIG_HOME"), home, ".config") {
        v = v.with_var("XDG_CONFIG_HOME", d);
    }
    if let Some(p) = project.or(cwd) {
        v = v.with_var("PROJECT", p);
    }
    if let Some(d) = found.data_dir {
        v = v.with_var("SAIIFE_DATA_DIR", d);
    }
    if let Some(d) = found.audit_dir {
        v = v.with_var("SAIIFE_AUDIT_DIR", d);
    }
    // The binary answering this hook and the `saiife` on PATH (usually
    // the same file once resolved).
    if let Ok(exe) = std::env::current_exe() {
        v = v.with_var("SAIIFE_BIN", exe);
    }
    if let Some(p) = found.saiife {
        v = v.with_var("SAIIFE_BIN", p);
    }
    for (name, default) in SYSTEM_PATHS {
        v = v.with_var(name, default);
    }
    if let Some(l) = locked {
        v = v
            .with_var("SAIIFE_ETC", &l.etc)
            .with_var("SAIIFE_AUDIT_DIR", &l.audit_dir)
            .with_var("SAIIFE_RUN", &l.socket_dir);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    /// An absolute path on this host.
    fn host_absolute() -> &'static str {
        if cfg!(windows) {
            r"C:\opt\x"
        } else {
            "/opt/x"
        }
    }

    #[test]
    fn config_dir_falls_back_to_the_default_under_home() {
        let home = || Some(PathBuf::from("/home/u"));
        let want = Some(PathBuf::from("/home/u").join(".claude"));
        assert_eq!(config_dir(None, home(), ".claude"), want);
        assert_eq!(config_dir(Some(OsString::new()), home(), ".claude"), want);
        assert_eq!(config_dir(Some("rel/dir".into()), home(), ".claude"), want);
        let absolute = host_absolute();
        assert_eq!(
            config_dir(Some(absolute.into()), home(), ".claude"),
            Some(PathBuf::from(absolute))
        );
        assert_eq!(config_dir(None, None, ".claude"), None);
    }

    /// The defaults now come from `agent_paths`; they are the ones the
    /// literals gave (`~/.claude`, `~/.codex`) on every platform.
    #[test]
    fn agent_config_dirs_match_the_old_defaults() {
        let home = Path::new("/home/u");
        for windows in [false, true] {
            for (agent, old) in [(Agent::Claude, ".claude"), (Agent::Codex, ".codex")] {
                let want = config_dir(None, Some(home.to_path_buf()), old);
                assert_eq!(agent_config_dir(None, Some(home), agent, windows), want);
                assert_eq!(
                    agent_config_dir(Some("rel".into()), Some(home), agent, windows),
                    want
                );
                assert_eq!(
                    agent_config_dir(Some(host_absolute().into()), Some(home), agent, windows),
                    Some(PathBuf::from(host_absolute()))
                );
                assert_eq!(agent_config_dir(None, None, agent, windows), None);
            }
        }
    }

    #[test]
    fn windows_variables_are_bound_in_windows_style() {
        let env = |name: &str| match name {
            "USERPROFILE" => Some(OsString::from(r"C:\Users\a")),
            "LOCALAPPDATA" => Some(OsString::from(r"C:\Users\a\AppData\Local")),
            "APPDATA" => Some(OsString::from(r"C:\Users\a\AppData\Roaming")),
            "TEMP" => Some(OsString::from(r"C:\Users\a\AppData\Local\Temp")),
            _ => None,
        };
        let v = bind_windows_vars(PathVars::new(), env);
        assert_eq!(v.style(), PathStyle::Windows);
        assert_eq!(v.home(), Some(Path::new("c:/Users/a")));
        for (name, want) in [
            ("LOCALAPPDATA", "c:/Users/a/AppData/Local"),
            ("APPDATA", "c:/Users/a/AppData/Roaming"),
            ("TEMP", "c:/Users/a/AppData/Local/Temp"),
        ] {
            assert_eq!(v.values(name), vec![Path::new(want)], "{name}");
        }
        assert!(v.values("PROGRAMDATA").is_empty());
    }

    #[test]
    #[cfg(not(windows))]
    fn the_cli_uses_posix_style_off_windows() {
        assert_eq!(path_vars(None, None).style(), PathStyle::Posix);
    }

    #[test]
    fn binds_cwd_project_and_the_running_binary() {
        let d = tempfile::tempdir().unwrap();
        let real = std::fs::canonicalize(d.path()).unwrap();
        let v = path_vars(Some(d.path()), None);
        // Each compared in the form this host's rules read it (Windows:
        // `d:/x`, where `fs::canonicalize` gives `\\\\?\\D:\\x`).
        let read = |p: &Path| {
            PathVars::new()
                .with_style(PathStyle::host())
                .with_var("X", p)
        };
        let form = |p: &Path| read(p).values("X")[0].to_path_buf();
        assert_eq!(v.cwd(), Some(form(&real).as_path()));
        // Both the spelled and the resolved value are bound (they differ on
        // macOS, where the temp dir is `/var/…` -> `/private/var/…`).
        assert!(v.values("PROJECT").contains(&form(&real).as_path()));
        assert!(read(d.path())
            .values("X")
            .iter()
            .all(|p| v.values("PROJECT").contains(p)));
        let exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        assert!(v.values("SAIIFE_BIN").contains(&form(&exe).as_path()));
        assert!(path_vars(None, None).cwd().is_none());
    }

    // Locked mode with the POSIX system paths; Windows has none until plan 19b.
    #[cfg(unix)]
    #[test]
    fn locked_paths_add_values() {
        let d = tempfile::tempdir().unwrap();
        let real = std::fs::canonicalize(d.path()).unwrap();
        let locked = LockedPaths {
            etc: real.join("etc"),
            audit_dir: real.join("audit"),
            socket_dir: real.join("run"),
        };
        let v = path_vars_locked(Some(&real), None, Some(&locked));
        let audit = v.values("SAIIFE_AUDIT_DIR");
        assert!(audit.contains(&real.join("audit").as_path()), "{audit:?}");
        if let Some(d) = store::default_dir() {
            assert!(audit.contains(&d.as_path()), "{audit:?}");
        }
        let etc = v.values("SAIIFE_ETC");
        assert!(etc.contains(&Path::new("/etc/saiife")), "{etc:?}");
        assert!(etc.contains(&real.join("etc").as_path()), "{etc:?}");
        let run = v.values("SAIIFE_RUN");
        // The platform's system run dir (`/var/db/saiife-run` on macOS).
        let sys_run = SYSTEM_PATHS
            .iter()
            .find(|(n, _)| *n == "SAIIFE_RUN")
            .unwrap()
            .1;
        assert!(run.contains(&Path::new(sys_run)), "{run:?}");
        assert!(run.contains(&real.join("run").as_path()), "{run:?}");
    }

    #[test]
    fn system_paths_macos_values() {
        use saiife_system::layout::{self, macos_path};
        let mac = system_paths(Platform::Macos);
        assert_eq!(
            mac,
            [
                ("SAIIFE_ETC", "/etc/saiife"),
                ("SAIIFE_STATE", "/var/db/saiife"),
                ("SAIIFE_LOG", "/var/log/saiife"),
                ("SAIIFE_RUN", "/var/db/saiife-run"),
                ("SAIIFE_OPT", "/opt/saiife"),
                (
                    "SAIIFE_UNIT",
                    "/Library/LaunchDaemons/com.saiife.saiifed.plist"
                ),
            ]
        );
        // Each value is the layout's macOS path of the Linux one.
        for ((name, linux), (_, m)) in system_paths(Platform::Linux).into_iter().zip(mac) {
            assert_eq!(macos_path(linux).unwrap_or(linux), m, "{name}");
        }
        let l = layout::Layout::under_for("/", Platform::Macos);
        assert_eq!(mac[3].1, l.logical(layout::RUN_DIR));
        #[cfg(target_os = "macos")]
        assert_eq!(SYSTEM_PATHS, mac);
        #[cfg(target_os = "linux")]
        assert_eq!(SYSTEM_PATHS, system_paths(Platform::Linux));
    }

    #[test]
    fn system_paths_windows_values() {
        let w = system_paths(Platform::Windows);
        assert_eq!(w[0], ("SAIIFE_ETC", r"C:\ProgramData\saiife\etc"));
        assert_eq!(w[4], ("SAIIFE_OPT", r"C:\ProgramData\saiife"));
        assert!(w
            .iter()
            .all(|(_, v)| v.starts_with(r"C:\ProgramData\saiife")));
        // Each value is the layout's Windows path of the Linux constant; the
        // two names with no Windows path bind what stands in for them.
        use saiife_system::layout::{windows_path, BINARY, ETC_DIR, LOG_DIR, OPT_DIR, STATE_DIR};
        for ((name, value), linux) in [
            (w[0], ETC_DIR),
            (w[1], STATE_DIR),
            (w[2], LOG_DIR),
            (w[4], OPT_DIR),
        ] {
            assert_eq!(windows_path(linux), Some(value), "{name}");
        }
        assert_eq!(
            w[3],
            ("SAIIFE_RUN", saiife_policy::system::WINDOWS_SOCKET_DIR)
        );
        assert_eq!(w[5], ("SAIIFE_UNIT", windows_path(BINARY).unwrap()));
        #[cfg(windows)]
        assert_eq!(SYSTEM_PATHS, w);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn system_paths_are_always_bound_to_their_defaults() {
        let v = path_vars(None, None);
        for (name, want) in [
            ("SAIIFE_ETC", "/etc/saiife"),
            ("SAIIFE_STATE", "/var/lib/saiife"),
            ("SAIIFE_LOG", "/var/log/saiife"),
            ("SAIIFE_RUN", "/run/saiife"),
            ("SAIIFE_OPT", "/opt/saiife"),
            ("SAIIFE_UNIT", "/etc/systemd/system/saiifed.service"),
        ] {
            assert!(
                v.values(name).contains(&Path::new(want)),
                "{name}: {:?}",
                v.values(name)
            );
        }
        assert!(v.values("SAIIFE_ETC").len() <= 2);
        // `XDG_CONFIG_HOME`: the variable when set and absolute, else
        // `~/.config` (the same rule as the agent config dirs).
        assert_eq!(
            config_dir(None, Some(PathBuf::from("/home/u")), ".config"),
            Some(PathBuf::from("/home/u/.config"))
        );
        if saiife_win::profile::home_dir().is_some() {
            assert!(!v.values("XDG_CONFIG_HOME").is_empty());
        }
    }

    /// This process's environment as a list binds what `path_vars_locked` binds.
    #[test]
    #[cfg(unix)]
    fn env_list_of_this_process_binds_the_same() {
        let env: Vec<_> = std::env::vars_os().collect();
        let cwd = Path::new("/srv/p");
        let locked = LockedPaths {
            etc: "/x/etc".into(),
            audit_dir: "/x/audit".into(),
            socket_dir: "/x/run".into(),
        };
        assert_eq!(
            format!("{:?}", path_vars_locked(Some(cwd), None, Some(&locked))),
            format!(
                "{:?}",
                path_vars_locked_env(Some(cwd), None, Some(&locked), &env)
            )
        );
    }

    /// A worker's environment (the account's home, nothing else) binds the account's
    /// dirs, whatever this process's environment says.
    #[test]
    #[cfg(all(unix, not(target_os = "macos")))]
    fn env_list_is_the_only_source() {
        let env: Vec<(OsString, OsString)> = [
            ("HOME", "/home/other"),
            ("USER", "other"),
            ("PATH", "/nonexistent-bin"),
            ("LANG", "C"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        let v = path_vars_locked_env(None, None, None, &env);
        let one = |name: &str| v.values(name).first().map(|p| p.to_path_buf());
        let at = |p: &str| Some(PathBuf::from(p));
        assert_eq!(one("HOME"), at("/home/other"));
        assert_eq!(one("CLAUDE_CONFIG_DIR"), at("/home/other/.claude"));
        assert_eq!(one("CODEX_HOME"), at("/home/other/.codex"));
        assert_eq!(one("XDG_CONFIG_HOME"), at("/home/other/.config"));
        assert_eq!(
            one("SAIIFE_DATA_DIR"),
            at("/home/other/.local/share/saiife")
        );
        assert_eq!(
            one("SAIIFE_AUDIT_DIR"),
            at("/home/other/.local/share/saiife/audit")
        );
        // No `saiife` on that PATH: only this binary.
        assert_eq!(
            v.values("SAIIFE_BIN"),
            vec![std::env::current_exe().unwrap().as_path()]
        );
        // Set or not, the variables an agent could move are taken from the list.
        let moved: Vec<(OsString, OsString)> = env
            .iter()
            .cloned()
            .chain(
                [
                    ("CLAUDE_CONFIG_DIR", "/elsewhere/c"),
                    ("XDG_DATA_HOME", "/elsewhere/d"),
                ]
                .map(|(k, v)| (k.into(), v.into())),
            )
            .collect();
        let v = path_vars_locked_env(None, None, None, &moved);
        assert_eq!(
            v.values("CLAUDE_CONFIG_DIR"),
            vec![Path::new("/elsewhere/c")]
        );
        assert_eq!(
            v.values("SAIIFE_DATA_DIR"),
            vec![Path::new("/elsewhere/d/saiife")]
        );
        // An empty list binds no home at all.
        let v = path_vars_locked_env(None, None, None, &[]);
        assert!(v.values("HOME").is_empty());
        assert!(v.values("CLAUDE_CONFIG_DIR").is_empty());
    }
}
