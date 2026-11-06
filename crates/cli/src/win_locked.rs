//! What the CLI's locked mode needs that differs on Windows (plan 19b, Task 10): whether a
//! system file may be believed, where the control pipe is and who must own it, and the
//! environment of the hook's worker. The rules are pure and run in Linux tests; the calls
//! behind them run on Windows only.
//!
//! Off Windows a system file needs no check here: it lies in a tree only root can write.
//! [`system_file_trust`] is `Trusted` there without a system call, so the hook's
//! path on Linux and macOS costs nothing.

use saiife_system::wintrust::Trust;
use std::path::Path;

/// What the descriptors of `path` and of the folders above it say.
pub(crate) fn system_file_trust(path: &Path) -> Trust {
    #[cfg(windows)]
    {
        let path = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
        saiife_system::wintrust::system_file(
            &saiife_system::Layout::system(),
            &path,
            &|p| saiife_win::ffi::acl::get_sddl(p),
            saiife_system::wintrust::test_trust_sid().as_deref(),
            &|| saiife_system::wintrust::service_registered(&saiife_system::host::RealHost),
        )
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Trust::Trusted
    }
}

/// `Ok` for a file that may be read as a system file, or that is not there; every
/// reader then says for itself what a missing file means. `Err` names the path and says
/// why, for the callers where a failed check is an error whatever the cause.
pub(crate) fn check_trusted(trust: &dyn Fn(&Path) -> Trust, path: &Path) -> Result<(), String> {
    match trust(path) {
        Trust::Absent | Trust::Trusted => Ok(()),
        Trust::NotOurs(why) | Trust::Damaged(why) => Err(not_protected(path, &why)),
    }
}

/// The line for a system file that failed the check.
pub(crate) fn not_protected(path: &Path, why: &str) -> String {
    format!(
        "{} is not protected as a system file ({why})",
        path.display()
    )
}

/// The running user is an admin here: root, or an elevated token (W26).
pub(crate) fn own_is_root() -> bool {
    #[cfg(unix)]
    {
        rustix::process::geteuid().is_root()
    }
    #[cfg(windows)]
    {
        saiife_win::ffi::token::current().is_ok_and(|t| t.elevated_admin)
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// An auditor on Windows: an elevated admin, or a token that holds the audit group's SID
/// among the groups that count.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn auditor_on_windows(
    elevated_admin: bool,
    group_sids: &[String],
    audit_sid: Option<&str>,
) -> bool {
    elevated_admin || audit_sid.is_some_and(|sid| group_sids.iter().any(|g| g == sid))
}

/// The pipe to open and the SID that must own it: the layout's endpoint and the service's
/// SID, whatever the config says (W10, W11). `test_pipe` is the debug-build seam: the
/// test's own daemon on its own pipe, so the owner to expect is the runner.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn pipe_target(
    endpoint: &saiife_system::layout::Endpoint,
    test_pipe: Option<String>,
    own_sid: impl FnOnce() -> Option<String>,
) -> Result<(String, String), String> {
    use saiife_system::layout::Endpoint;
    if let Some(pipe) = test_pipe {
        let own = own_sid().ok_or("cannot read this process's own SID")?;
        return Ok((pipe, own));
    }
    match endpoint {
        Endpoint::Pipe(name) => Ok((
            name.clone(),
            saiife_win::sid::service_sid(saiife_system::layout::WIN_SERVICE),
        )),
        Endpoint::Unix(p) => Err(format!("{} is no pipe", p.display())),
    }
}

/// The personal broker's pipe and the SID that must own it: this user's in both places
/// (W25). `test_pipe` is the debug-build seam, whose owner to expect is the runner, so the
/// seam changes the name and never the owner.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn personal_pipe_target(
    test_pipe: Option<String>,
    own_sid: &str,
) -> Result<(String, String), String> {
    let pipe = match test_pipe {
        Some(pipe) => pipe,
        None => saiife_system::personal::personal_pipe_name(own_sid)?,
    };
    Ok((pipe, own_sid.to_string()))
}

/// `ProfileImagePath` of a profile as a home directory. The value is `REG_EXPAND_SZ`, and
/// the only variable Windows writes there is `%SystemRoot%` (for the service accounts).
/// Anything else, or a path not on a drive, is `None`: the caller denies.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn profile_home(raw: &str, system_root: &str) -> Option<String> {
    const VAR: &str = "%systemroot%";
    let expanded = match raw.get(..VAR.len()) {
        Some(head) if head.eq_ignore_ascii_case(VAR) => {
            format!("{system_root}{}", &raw[VAR.len()..])
        }
        _ => raw.to_string(),
    };
    let b = expanded.as_bytes();
    let on_a_drive = b.len() >= 3 && b[0].is_ascii_alphabetic() && &b[1..3] == b":\\";
    (on_a_drive && !expanded.contains('%')).then_some(expanded)
}

/// The worker's whole environment on Windows, in place of what the agent started with.
///
/// An agent that sets `USERPROFILE` must not move the path rules, as `HOME` must not on
/// Linux: `home` comes from the machine's own record of this SID, and the folders are the
/// ones W9 fixes (install refuses other system folders). What a user redirected on their
/// own is not followed: nobody but the user vouches for that.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn worker_env(home: &str, system_root: &str) -> Vec<(&'static str, String)> {
    let local = format!(r"{home}\AppData\Local");
    let temp = format!(r"{local}\Temp");
    vec![
        ("USERPROFILE", home.to_string()),
        ("HOME", home.to_string()),
        ("LOCALAPPDATA", local),
        ("APPDATA", format!(r"{home}\AppData\Roaming")),
        ("TEMP", temp.clone()),
        ("TMP", temp),
        ("PROGRAMDATA", r"C:\ProgramData".to_string()),
        ("ALLUSERSPROFILE", r"C:\ProgramData".to_string()),
        ("PROGRAMFILES", r"C:\Program Files".to_string()),
        ("PROGRAMFILES(X86)", r"C:\Program Files (x86)".to_string()),
        ("SYSTEMDRIVE", "C:".to_string()),
        ("SYSTEMROOT", system_root.to_string()),
        ("PATH", format!(r"{system_root}\System32;{system_root}")),
    ]
}

/// The key of a SID's profile below HKLM. Only an administrator can change it.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn profile_key(sid: &str) -> String {
    format!(
        r"{}\ProfileList\{sid}",
        saiife_system::host::REG_NT_CURRENT_VERSION
    )
}

/// The system daemon's pipe, and the owner it must have.
#[cfg(windows)]
pub(crate) fn control_target() -> Result<(String, String), String> {
    #[cfg(debug_assertions)]
    let test_pipe = std::env::var("SAIIFE_TEST_PIPE").ok();
    #[cfg(not(debug_assertions))]
    let test_pipe = None;
    pipe_target(
        &saiife_system::Layout::system().control_endpoint(),
        test_pipe,
        || saiife_win::ffi::token::current().ok().map(|t| t.sid),
    )
}

/// The personal broker's pipe, and the owner it must have.
#[cfg(windows)]
pub(crate) fn personal_target() -> Result<(String, String), String> {
    #[cfg(debug_assertions)]
    let test_pipe = std::env::var("SAIIFE_TEST_PIPE").ok();
    #[cfg(not(debug_assertions))]
    let test_pipe = None;
    let token = saiife_win::ffi::token::current()
        .map_err(|e| format!("cannot read this process's token: {e}"))?;
    personal_pipe_target(test_pipe, &token.sid)
}

/// The running user's canonical `DOMAIN\name`, as the daemon names its peer.
#[cfg(windows)]
pub(crate) fn own_account_name() -> Option<String> {
    let token = saiife_win::ffi::token::current().ok()?;
    saiife_win::ffi::account::lookup_sid(&token.sid).ok()
}

/// The environment for the worker, or why there can be none.
#[cfg(windows)]
pub(crate) fn worker_environment() -> Result<Vec<(&'static str, String)>, String> {
    use saiife_system::host::{Host, RealHost, REG_NT_CURRENT_VERSION};
    let token = saiife_win::ffi::token::current().map_err(|e| format!("no token: {e}"))?;
    let host = RealHost;
    let system_root = host
        .reg_string(REG_NT_CURRENT_VERSION, "SystemRoot")
        .ok_or("the machine's SystemRoot cannot be read")?;
    let home = host
        .reg_string(&profile_key(&token.sid), "ProfileImagePath")
        .and_then(|raw| profile_home(&raw, &system_root))
        .ok_or_else(|| format!("no profile on record for {}", token.sid))?;
    Ok(worker_env(&home, &system_root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use saiife_system::layout::{Endpoint, Layout, Platform, WIN_PIPE};

    #[test]
    fn the_pipe_must_be_owned_by_the_service() {
        let l = Layout::under_for("/x", Platform::Windows);
        let (name, owner) = pipe_target(&l.control_endpoint(), None, || {
            panic!("no SID is read without the seam")
        })
        .unwrap();
        assert_eq!(name, WIN_PIPE);
        assert_eq!(owner, saiife_win::sid::service_sid("saiifed"));
    }

    #[test]
    fn the_test_pipe_expects_the_runner() {
        let l = Layout::under_for("/x", Platform::Windows);
        let got = pipe_target(
            &l.control_endpoint(),
            Some(r"\\.\pipe\saiife-test-1".into()),
            || Some("S-1-5-21-1".into()),
        );
        assert_eq!(
            got,
            Ok((
                r"\\.\pipe\saiife-test-1".to_string(),
                "S-1-5-21-1".to_string()
            ))
        );
        // No SID: no owner to check against, so no connection.
        assert!(pipe_target(&l.control_endpoint(), Some("p".into()), || None).is_err());
    }

    /// The name and the owner both come from the SID, and the owner is never the service's:
    /// a client of the personal broker must not accept the system daemon, nor the reverse.
    #[test]
    fn the_personal_pipe_must_be_owned_by_this_user() {
        const ME: &str = "S-1-5-21-1111-2222-3333-1001";
        let (name, owner) = personal_pipe_target(None, ME).unwrap();
        assert_eq!(name, format!(r"\\.\pipe\saiife-user-{ME}"));
        assert_eq!(owner, ME);
        assert_ne!(name, WIN_PIPE);
        assert_ne!(owner, saiife_win::sid::service_sid("saiifed"));
        // What a daemon of the same user opens, so the two sides meet.
        assert_eq!(
            name,
            saiife_system::personal::personal_pipe_name(ME).unwrap()
        );
        // The seam moves the name, not the owner.
        let (name, owner) = personal_pipe_target(Some("p".into()), ME).unwrap();
        assert_eq!((name.as_str(), owner.as_str()), ("p", ME));
        // A token whose SID is no SID makes no name.
        assert!(personal_pipe_target(None, r"..\evil").is_err());
    }

    #[test]
    fn a_socket_endpoint_is_no_pipe() {
        let e = Endpoint::Unix("/run/saiife/saiife.sock".into());
        assert!(pipe_target(&e, None, || None).is_err());
    }

    #[test]
    fn profile_paths() {
        let root = r"C:\Windows";
        assert_eq!(
            profile_home(r"C:\Users\alice", root).as_deref(),
            Some(r"C:\Users\alice")
        );
        assert_eq!(
            profile_home(r"%SystemRoot%\system32\config\systemprofile", root).as_deref(),
            Some(r"C:\Windows\system32\config\systemprofile")
        );
        assert_eq!(
            profile_home(r"%systemroot%\x", root).as_deref(),
            Some(r"C:\Windows\x")
        );
        for bad in [
            "",
            r"%USERPROFILE%\x",
            r"\\srv\home\alice",
            r"C:\a\%b%",
            "alice",
            "C:x",
        ] {
            assert_eq!(profile_home(bad, root), None, "{bad}");
        }
    }

    /// Everything the path rules read is set, from the record and the fixed folders, so
    /// nothing the agent's environment held can reach the worker.
    #[test]
    fn the_worker_environment_is_whole() {
        let env = worker_env(r"C:\Users\alice", r"C:\Windows");
        let get = |k: &str| {
            env.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.as_str())
                .unwrap_or_else(|| panic!("{k}"))
        };
        assert_eq!(get("USERPROFILE"), r"C:\Users\alice");
        assert_eq!(get("LOCALAPPDATA"), r"C:\Users\alice\AppData\Local");
        assert_eq!(get("TEMP"), r"C:\Users\alice\AppData\Local\Temp");
        assert_eq!(get("PROGRAMDATA"), r"C:\ProgramData");
        assert_eq!(get("SYSTEMROOT"), r"C:\Windows");
        for gone in [
            "CLAUDE_CONFIG_DIR",
            "CODEX_HOME",
            "XDG_CONFIG_HOME",
            "SAIIFE_DATA_DIR",
        ] {
            assert!(!env.iter().any(|(n, _)| *n == gone), "{gone}");
        }
    }

    #[test]
    fn an_auditor_holds_the_group_or_is_elevated() {
        let groups = [
            "S-1-5-32-545".to_string(),
            "S-1-5-21-1-2-3-1009".to_string(),
        ];
        assert!(auditor_on_windows(
            false,
            &groups,
            Some("S-1-5-21-1-2-3-1009")
        ));
        assert!(!auditor_on_windows(false, &groups, Some("S-1-5-21-9")));
        // The group cannot be found: nobody but an admin.
        assert!(!auditor_on_windows(false, &groups, None));
        assert!(auditor_on_windows(true, &[], None));
    }

    #[test]
    fn check_trusted_refuses_both_failures() {
        let p = Path::new("/x/config.toml");
        assert_eq!(check_trusted(&|_| Trust::Trusted, p), Ok(()));
        assert_eq!(check_trusted(&|_| Trust::Absent, p), Ok(()));
        for t in [Trust::NotOurs("a".into()), Trust::Damaged("a".into())] {
            let e = check_trusted(&|_| t.clone(), p).unwrap_err();
            assert!(e.contains("config.toml"), "{e}");
        }
    }
}
