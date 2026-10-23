//! What the developer hook (`saiife check` without `--managed`) needs from
//! `/etc/saiife`: which agents have a managed hook (their project hook then
//! goes quiet, spec §6.1.1) and whether this machine asks for fail closed
//! (spec §11). Read on every hook call, so it stays cheap: the config is
//! read as a raw TOML table, never through the full policy loader, and a
//! missing file costs one failed open.

use std::io::Read;
use std::path::Path;

use saiife_policy::installed::read_installed;

use crate::warn;

/// Largest system file read here.
const MAX_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SystemView {
    /// Agents `installed.toml` lists a managed hook for.
    pub managed_agents: Vec<String>,
    /// `locked = true`, or `[guard] fail = "closed"` set explicitly.
    pub fail_closed: bool,
}

/// Reads `config` and the `installed.toml` next to it. A missing file reads
/// as the v1 default (nothing managed, fail open). An invalid one reads as
/// the v1 default too, with one warning on stderr.
pub fn read(config: &Path) -> SystemView {
    let mut view = SystemView::default();
    match read_regular(config, false, MAX_BYTES).and_then(|b| b.map(parse_config).transpose()) {
        Ok(Some(closed)) => view.fail_closed = closed,
        Ok(None) => {}
        Err(e) => ignored(config, &e),
    }
    let installed = config
        .parent()
        .unwrap_or(Path::new("/"))
        .join("installed.toml");
    match read_installed(&installed) {
        Ok(Some(i)) => view.managed_agents = i.agents.into_iter().map(|a| a.agent).collect(),
        Ok(None) => {}
        Err(e) => {
            // `read_installed` names the path itself.
            let prefix = format!("{}: ", installed.display());
            ignored(&installed, e.strip_prefix(&prefix).unwrap_or(&e));
        }
    }
    view
}

fn ignored(path: &Path, error: &str) {
    warn(&format!("warning: {} ignored: {error}", path.display()));
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
        let v = read(&c);
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
            assert_eq!(view(Some(text)).1.fail_closed, closed, "{text}");
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

    #[test]
    fn oversized_file_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let c = d.path().join("config.toml");
        std::fs::write(&c, "x".repeat(2048)).unwrap();
        assert!(read_regular(&c, false, 1024).is_err());
        assert!(read_regular(&c, false, 2048).unwrap().is_some());
    }
}
