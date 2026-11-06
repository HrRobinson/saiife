//! What the developer hook (`saiife check` without `--managed`) needs from
//! `/etc/saiife`: which agents have a managed hook (their project hook then
//! goes quiet, spec §6.1.1) and whether this machine asks for fail closed
//! (spec §11). Read on every hook call, so it stays cheap: the config is
//! read as a raw TOML table, never through the full policy loader, and a
//! missing file costs one failed open.

use std::io::Read;
use std::path::Path;

use saiife_agents::lock::replaces_project_hook;
use saiife_policy::installed::read_installed;
use saiife_system::wintrust::Trust;

use crate::warn;

/// Largest system file read here.
const MAX_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SystemView {
    /// Agents whose managed hook replaces the project hook: listed in
    /// `installed.toml` with a fingerprint, and lockable
    /// ([`saiife_agents::lock::replaces_project_hook`]).
    pub managed_agents: Vec<String>,
    /// `locked = true`, or `[guard] fail = "closed"` set explicitly.
    pub fail_closed: bool,
    /// One `warning: <path> ignored: <error>` per invalid file, for the
    /// caller to print once it knows the hook is not quiet.
    pub warnings: Vec<String>,
}

impl SystemView {
    /// `agent` has a managed hook: its project hook stays quiet.
    pub fn is_managed(&self, agent: &str) -> bool {
        self.managed_agents.iter().any(|a| a == agent)
    }

    /// Print the warnings on stderr (once per call).
    pub fn print_warnings(&self) {
        for w in &self.warnings {
            warn(w);
        }
    }
}

/// Reads `config` and the `installed.toml` next to it. A missing file reads
/// as the v1 default (nothing managed, fail open). An invalid one reads as
/// the v1 default too, with one warning in `warnings`.
pub fn read(config: &Path) -> SystemView {
    read_with(&crate::win_locked::system_file_trust, config)
}

/// [`read`] with the DACL check given. On Windows ProgramData is not root-owned, so a
/// file there counts only once its descriptors say no non-admin could have written it:
///
/// - `config.toml` on a tree that is not ours is ignored, with a warning: anyone could
///   have planted it, and it cannot make every other user's hook fail closed. On our
///   tree it is damaged, so this reads as a locked host: fail closed, with a warning.
/// - `installed.toml` that fails is ignored either way, with a warning: no agent is
///   managed, so the project hooks stay on.
fn read_with(trust: &dyn Fn(&Path) -> Trust, config: &Path) -> SystemView {
    read_on(trust, config, cfg!(windows))
}

/// [`read_with`] with the OS given. Any user may read the config on Windows, and so may
/// hold it open with no sharing: a read that fails there says nothing about what the file
/// holds, and must not open the hook. A file that is not ours stays ignored, so a planted
/// and locked one cannot fail every other user's hook closed.
fn read_on(trust: &dyn Fn(&Path) -> Trust, config: &Path, windows: bool) -> SystemView {
    let mut view = SystemView::default();
    match read_regular(config, false, MAX_BYTES) {
        Ok(None) => {}
        Err(e) => {
            view.fail_closed =
                windows && matches!(trust(config), Trust::Trusted | Trust::Damaged(_));
            view.warnings.push(ignored(config, &e));
        }
        Ok(Some(bytes)) => match trust(config) {
            Trust::NotOurs(why) => view.warnings.push(ignored(config, &unprotected(&why))),
            Trust::Damaged(why) => {
                view.fail_closed = true;
                view.warnings.push(ignored(config, &unprotected(&why)));
            }
            Trust::Absent | Trust::Trusted => match parse_config(bytes) {
                Ok(closed) => view.fail_closed = closed,
                Err(e) => view.warnings.push(ignored(config, &e)),
            },
        },
    }
    read_installed_into(trust, config, &mut view);
    view
}

fn unprotected(why: &str) -> String {
    format!("not protected as a system file ({why})")
}

fn read_installed_into(trust: &dyn Fn(&Path) -> Trust, config: &Path, view: &mut SystemView) {
    let installed = config
        .parent()
        .unwrap_or(Path::new("/"))
        .join("installed.toml");
    match trust(&installed) {
        Trust::Absent => return,
        Trust::Trusted => {}
        Trust::NotOurs(why) | Trust::Damaged(why) => {
            view.warnings.push(ignored(&installed, &unprotected(&why)));
            return;
        }
    }
    match read_installed(&installed) {
        Ok(Some(i)) => {
            view.managed_agents = i
                .agents
                .into_iter()
                .filter(|a| replaces_project_hook(&a.agent, &a.sha256))
                .map(|a| a.agent)
                .collect()
        }
        Ok(None) => {}
        Err(e) => {
            // `read_installed` names the path itself.
            let prefix = format!("{}: ", installed.display());
            let e = ignored(&installed, e.strip_prefix(&prefix).unwrap_or(&e));
            view.warnings.push(e);
        }
    }
}

fn ignored(path: &Path, error: &str) -> String {
    format!("warning: {} ignored: {error}", path.display())
}

/// `fail_closed` from the config's bytes.
fn parse_config(bytes: Vec<u8>) -> Result<bool, String> {
    let text = String::from_utf8(bytes).map_err(|_| "not valid UTF-8".to_string())?;
    let table: toml::Table = text
        .parse()
        .map_err(|e: toml::de::Error| e.message().to_string())?;
    let locked = table.get("locked").and_then(toml::Value::as_bool) == Some(true);
    let closed = table
        .get("guard")
        .and_then(toml::Value::as_table)
        .and_then(|g| g.get("fail"))
        .and_then(toml::Value::as_str)
        == Some("closed");
    Ok(locked || closed)
}

/// The bytes of `path`, `Ok(None)` when it does not exist. The open never
/// blocks (a FIFO cannot hang the caller) and follows a symlink only when
/// `follow` is set; only a regular file of at most `max` bytes is read. The
/// error does not name the path.
pub(crate) fn read_regular(path: &Path, follow: bool, max: u64) -> Result<Option<Vec<u8>>, String> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let nofollow = if follow { 0 } else { libc::O_NOFOLLOW };
        opts.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | nofollow);
    }
    let not_regular = || {
        if follow {
            "not a regular file".to_string()
        } else {
            "not a regular file (symlinks are not followed)".to_string()
        }
    };
    let file = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        #[cfg(unix)]
        Err(e) if !follow && e.raw_os_error() == Some(libc::ELOOP) => return Err(not_regular()),
        Err(e) => return Err(e.to_string()),
    };
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err(not_regular());
    }
    let too_big = || format!("larger than {} KiB", max / 1024);
    if meta.len() > max {
        return Err(too_big());
    }
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > max {
        return Err(too_big());
    }
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(config: Option<&str>) -> (tempfile::TempDir, SystemView) {
        let d = tempfile::tempdir().unwrap();
        let c = d.path().join("config.toml");
        if let Some(t) = config {
            std::fs::write(&c, t).unwrap();
        }
        let v = read_with(&|_: &Path| Trust::Trusted, &c);
        (d, v)
    }

    #[test]
    fn missing_files_are_the_v1_default() {
        assert_eq!(view(None).1, SystemView::default());
    }

    #[test]
    fn fail_closed_only_when_set() {
        for (text, closed) in [
            ("version = 2\n", false),
            ("version = 2\n[guard]\nfail = \"open\"\n", false),
            ("version = 2\n[guard]\nfail = \"closed\"\n", true),
            ("version = 2\nlocked = true\n", true),
            ("version = 2\nlocked = false\n", false),
            ("version = 2\nlocked = \"true\"\n", false),
            ("version = = 2\n[guard]\nfail = \"closed\"\n", false),
        ] {
            let (_d, v) = view(Some(text));
            assert_eq!(v.fail_closed, closed, "{text}");
            assert_eq!(
                v.warnings.len(),
                usize::from(text.contains("= =")),
                "{text}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_config_is_not_followed() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real.toml");
        std::fs::write(&real, "locked = true\n").unwrap();
        let c = d.path().join("config.toml");
        std::os::unix::fs::symlink(&real, &c).unwrap();
        assert!(!read(&c).fail_closed);
        assert_eq!(
            read_regular(&c, false, MAX_BYTES).unwrap_err(),
            "not a regular file (symlinks are not followed)"
        );
        assert!(read_regular(&c, true, MAX_BYTES).unwrap().is_some());
    }

    const INSTALLED_ONE: &str = "[[agents]]\nagent = \"claude\"\nsha256 = \"ab\"\n";

    /// `config` and `installed.toml` as files, read with `trust` as the DACL check.
    fn view_with(trust: &dyn Fn(&Path) -> Trust) -> (SystemView, SystemView) {
        let d = tempfile::tempdir().unwrap();
        let c = d.path().join("config.toml");
        std::fs::write(&c, "version = 2\nlocked = true\n").unwrap();
        let open = read_with(&|_: &Path| Trust::Trusted, &c);
        (open, read_with(trust, &c))
    }

    /// A file held open with no sharing reads as an error on Windows, and is no reason to
    /// open the hook. A directory in its place makes the read fail the same way here.
    #[test]
    fn an_unreadable_config_fails_closed_on_windows_only() {
        let d = tempfile::tempdir().unwrap();
        let c = d.path().join("config.toml");
        std::fs::create_dir(&c).unwrap();
        let trust = |t: Trust| move |_: &Path| t.clone();

        for t in [Trust::Trusted, Trust::Damaged("users may write".into())] {
            let v = read_on(&trust(t), &c, true);
            assert!(v.fail_closed);
            assert!(!v.warnings.is_empty());
        }
        // Linux and macOS stay as they were, and nothing planted closes anyone's hook.
        let v = read_on(&trust(Trust::Trusted), &c, false);
        assert!(!v.fail_closed);
        let v = read_on(&trust(Trust::NotOurs("planted".into())), &c, true);
        assert!(!v.fail_closed);
        assert!(!v.warnings.is_empty());
    }

    /// A planted `locked = true` on a tree that is not ours tightens nothing.
    #[test]
    fn a_planted_config_is_ignored() {
        let (open, v) = view_with(&|_: &Path| Trust::NotOurs("owned by me".into()));
        assert!(open.fail_closed);
        assert!(!v.fail_closed);
        assert_eq!(v.warnings.len(), 2, "{:?}", v.warnings);
        assert!(v.warnings[0].contains("owned by me"), "{:?}", v.warnings);
    }

    /// Our tree with a config open to the users is a locked host gone wrong.
    #[test]
    fn a_damaged_config_fails_closed_whatever_it_says() {
        let d = tempfile::tempdir().unwrap();
        let c = d.path().join("config.toml");
        std::fs::write(&c, "version = 2\nlocked = false\n").unwrap();
        let v = read_with(&|_: &Path| Trust::Damaged("users may write".into()), &c);
        assert!(v.fail_closed);
        assert!(
            v.warnings[0].contains("users may write"),
            "{:?}",
            v.warnings
        );
    }

    /// A planted install record must not make a project hook go quiet.
    #[test]
    fn a_planted_install_record_silences_nothing() {
        let d = tempfile::tempdir().unwrap();
        let c = d.path().join("config.toml");
        let i = d.path().join("installed.toml");
        std::fs::write(&i, INSTALLED_ONE).unwrap();
        for bad in [
            Trust::NotOurs("planted".into()),
            Trust::Damaged("loose".into()),
        ] {
            let v = read_with(
                &|p: &Path| {
                    if p == i {
                        bad.clone()
                    } else {
                        Trust::Absent
                    }
                },
                &c,
            );
            assert!(v.managed_agents.is_empty(), "{v:?}");
            assert_eq!(v.warnings.len(), 1, "{v:?}");
        }
    }

    #[test]
    fn a_config_that_fails_the_check_is_not_even_parsed() {
        let d = tempfile::tempdir().unwrap();
        let c = d.path().join("config.toml");
        std::fs::write(&c, "not = = toml").unwrap();
        let v = read_with(&|_: &Path| Trust::NotOurs("planted".into()), &c);
        assert_eq!(v.warnings.len(), 2, "{v:?}");
        assert!(v.warnings.iter().all(|w| w.contains("planted")), "{v:?}");
    }

    #[test]
    fn oversized_file_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let c = d.path().join("config.toml");
        std::fs::write(&c, "x".repeat(2048)).unwrap();
        assert!(read_regular(&c, false, 1024).is_err());
        assert!(read_regular(&c, false, 2048).unwrap().is_some());
    }
}
