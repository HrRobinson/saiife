//! `saiife __box-vmm <dir> [--locked]` (plan 35, Task 4): reads the box's
//! `vm.json` (written by the daemon at each boot, in the VMM-writable
//! runtime dir; locked, one its own user owns is refused), refuses Landlock
//! off and sizes above the template ceilings, checks every path in it,
//! verifies the pinned binaries, then execs Cloud Hypervisor with stdout
//! and stderr in `ch.log`. Nothing runs unless every check passed. Exit 3: refused. Exit 4: exec failed.

use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(not(unix))]
pub fn run(_dir: PathBuf, _locked: bool) -> ExitCode {
    eprintln!("saiife __box-vmm: {}", saiife_system::NOT_SUPPORTED_OS);
    ExitCode::from(3)
}

#[cfg(unix)]
pub fn run(dir: PathBuf, locked: bool) -> ExitCode {
    match imp::prepare(dir, locked) {
        Ok(mut cmd) => {
            use std::os::unix::process::CommandExt;
            let e = cmd.exec();
            eprintln!("saiife __box-vmm: cannot exec: {e}");
            ExitCode::from(4)
        }
        Err(why) => {
            eprintln!("saiife __box-vmm: {}", crate::text::sanitize(&why));
            ExitCode::from(3)
        }
    }
}

#[cfg(unix)]
mod imp {
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    use saiife_boxhost::launch::{self, Allowed, Boot};
    use saiife_boxhost::layout::Layout;
    use saiife_boxhost::paths::BoxPaths;
    use saiife_boxhost::pins;
    use saiife_boxhost::tools::{Tool, Tools};

    fn env(k: &str) -> Option<OsString> {
        std::env::var_os(k)
    }

    /// The personal layout of the running user: the daemon's state dir
    /// (`personal_paths`, as `saiife daemon --user`) and the XDG data home.
    fn personal() -> Result<Layout, String> {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let paths = saiife_system::personal::personal_paths(&env, home.as_deref())?;
        let abs = |k: &str| env(k).map(PathBuf::from).filter(|p| p.is_absolute());
        let data_home = abs("XDG_DATA_HOME")
            .or_else(|| {
                home.as_deref()
                    .filter(|h| h.is_absolute())
                    .map(|h| h.join(".local/share"))
            })
            .ok_or("cannot find your data dir (HOME is not set)")?;
        Ok(Layout::personal(&paths.state_dir, &data_home))
    }

    pub(super) fn prepare(dir: PathBuf, locked: bool) -> Result<Command, String> {
        let layout = if locked {
            Layout::locked()
        } else {
            personal()?
        };
        let allowed = Allowed::for_layout(&layout);
        let paths = BoxPaths::new(dir);
        // locked: the daemon wrote vm.json; one this (VMM) user owns is not
        // the daemon's
        let me = rustix::process::geteuid().as_raw();
        let spec = launch::read_spec_owned(&paths, locked.then_some(me))?;
        // vm.json is in the VMM-writable runtime dir: fail closed on a
        // spec no daemon writes, before anything else
        launch::check_limits(&spec)?;
        launch::check_spec(&spec, &paths, &allowed)?;
        let tools = Tools::system(&layout.vmm).with_env(&env);
        let ch = tools.path(Tool::Ch).to_path_buf();
        if !launch::pin_check_skipped(&env) {
            pins::verify(&ch, pins::CH_SHA256)?;
            if let Boot::Firmware { fw } = &spec.boot {
                pins::verify(fw, pins::FW_SHA256)?;
            }
        }
        // The Landlock rule's snapshot dir, made as the VMM user.
        launch::ensure_snapshot_dir(&paths)?;
        let log = launch::open_ch_log(&paths.ch_log())?;
        let log2 = log.try_clone().map_err(|e| format!("ch.log: {e}"))?;
        let mut cmd = Command::new(&ch);
        cmd.args(launch::argv(&spec, &paths))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(log)
            .stderr(log2);
        Ok(cmd)
    }
}
