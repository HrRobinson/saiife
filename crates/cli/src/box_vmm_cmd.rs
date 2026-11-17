//! `saiife box vmm fetch|status` (plan 35): the pinned Cloud Hypervisor and
//! firmware. Exit codes as `saiife box`: 2 refused, 5 unavailable.

use std::path::PathBuf;

use clap::Subcommand;

#[derive(Subcommand)]
pub enum VmmAction {
    /// Download the pinned Cloud Hypervisor and firmware.
    Fetch {
        /// Where to put them (default: your saiife data dir).
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Show the pinned versions and whether the files match.
    Status,
}

// Refused is never built on non-unix, where run only answers Unavailable.
#[cfg_attr(not(unix), allow(dead_code))]
pub enum Fail {
    Refused(String),
    Unavailable(String),
}

/// Not reached off unix (`box_cmd::run` refuses first); kept for the API.
#[cfg(not(unix))]
#[allow(dead_code)]
pub fn run(_config: Option<&std::path::Path>, _action: VmmAction) -> Result<(), Fail> {
    Err(Fail::Unavailable(
        saiife_system::NOT_SUPPORTED_OS.to_string(),
    ))
}

#[cfg(unix)]
pub fn run(config: Option<&std::path::Path>, action: VmmAction) -> Result<(), Fail> {
    imp::run(config, action)
}

#[cfg(unix)]
mod imp {
    use super::{Fail, VmmAction};
    use crate::broker;
    use crate::text::sanitize;
    use saiife_boxhost::layout::Layout;
    use saiife_boxhost::pins;
    use saiife_boxhost::tools::Tools;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::{Path, PathBuf};

    const LOCKED_HINT: &str =
        "boxes are installed system-wide; run \"sudo saiife system install --boxes\"";

    /// The two things pinned, each with file name, version, URL, sha256, mode.
    const FILES: [(&str, &str, &str, &str, u32); 2] = [
        (
            "cloud-hypervisor",
            pins::CH_VERSION,
            pins::CH_URL,
            pins::CH_SHA256,
            0o755,
        ),
        (
            "CLOUDHV.fd",
            pins::FW_VERSION,
            pins::FW_URL,
            pins::FW_SHA256,
            0o644,
        ),
    ];

    fn abs_env(k: &str) -> Option<PathBuf> {
        std::env::var_os(k)
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    }

    fn personal_layout() -> Result<Layout, Fail> {
        let data_home = abs_env("XDG_DATA_HOME")
            .or_else(|| abs_env("HOME").map(|h| h.join(".local/share")))
            .ok_or_else(|| {
                Fail::Unavailable("cannot find your data dir (HOME is not set)".into())
            })?;
        // Only `vmm` is used; the state dir is not needed here.
        Ok(Layout::personal(&data_home, &data_home))
    }

    pub(super) fn run(config: Option<&Path>, action: VmmAction) -> Result<(), Fail> {
        let locked = broker::resolve_here(config)
            .map_err(Fail::Unavailable)?
            .is_locked();
        match action {
            VmmAction::Status => {
                let dir = if locked {
                    Layout::locked().vmm
                } else {
                    personal_layout()?.vmm
                };
                status(&dir);
                Ok(())
            }
            VmmAction::Fetch { dir } => {
                if locked {
                    return Err(Fail::Refused(LOCKED_HINT.into()));
                }
                let dir = match dir {
                    Some(d) => d,
                    None => personal_layout()?.vmm,
                };
                fetch(&dir)
            }
        }
    }

    fn status(dir: &Path) {
        outln!("vmm dir {}", sanitize(&dir.display().to_string()));
        for (name, version, _, sha, _) in FILES {
            let p = dir.join(name);
            let state = if std::fs::symlink_metadata(&p).is_err() {
                "missing".to_string()
            } else {
                match pins::verify(&p, sha) {
                    Ok(()) => "ok".to_string(),
                    Err(e) => format!("does not match the pin ({})", sanitize(&e)),
                }
            };
            outln!("{name} {version} {state}");
        }
    }

    fn fetch(dir: &Path) -> Result<(), Fail> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| Fail::Refused(format!("cannot create {}: {e}", dir.display())))?;
        let tools = Tools::system(dir).with_env(&|k| std::env::var_os(k));
        for (name, version, url, sha, mode) in FILES {
            pins::fetch(&tools, url, sha, &dir.join(name), mode).map_err(Fail::Refused)?;
            outln!("{name} {version} ok");
        }
        Ok(())
    }
}
