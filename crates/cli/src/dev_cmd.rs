//! `saiife dev up|ls|down|gc|ca` (plan 24): local compose stacks behind one
//! HTTPS proxy.
//!
//! The CLI only composes: every Docker, compose, route, cert and proxy step is
//! a `saiife_dev` function. This module parses the subcommand, builds the
//! `DevPaths` and the `DockerCli` once, asks for confirmations and prints.
//! Docker runs as the user, never through the daemon (spec §5.1).

use std::fs::{self, OpenOptions};
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Subcommand;
use saiife_dev::certs::ensure_ca;
use saiife_dev::docker::DockerCli;
use saiife_dev::paths::DevPaths;

use crate::text::sanitize;

mod inventory;
mod remove;
mod up;

#[derive(Subcommand)]
pub enum DevAction {
    /// Start the compose stack in DIR (default: here) behind the proxy.
    Up {
        /// The repo folder that holds the compose file (default: the current one).
        dir: Option<PathBuf>,
    },
    /// List every saiife dev environment, with its state and URLs.
    Ls {
        /// Print JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Stop a project and remove what saiife labelled for it.
    Down {
        /// The project name, as `saiife dev ls` shows it.
        project: String,
        /// Also delete the project's labelled volumes (asks first).
        #[arg(long)]
        volumes: bool,
        /// Answer yes to the volume question (for scripts).
        #[arg(long)]
        yes: bool,
    },
    /// Remove what saiife labelled for stopped and missing projects.
    Gc {
        /// Also delete labelled volumes that no container uses (asks first).
        #[arg(long)]
        volumes: bool,
        /// Answer yes to the volume question (for scripts).
        #[arg(long)]
        yes: bool,
    },
    /// Show where the local CA certificate is and how to trust it.
    Ca,
}

/// What a step returns: `Err` is the sentence printed after `saiife dev: `.
pub(crate) type Res = Result<(), String>;

pub fn run(action: DevAction) -> ExitCode {
    match dispatch(action) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("saiife dev: {}", sanitize(msg.trim_end()));
            ExitCode::from(1)
        }
    }
}

fn dispatch(action: DevAction) -> Result<ExitCode, String> {
    let paths = DevPaths::from_env().map_err(|e| e.to_string())?;
    // `ca` never needs Docker, so it works where Docker is not installed.
    if let DevAction::Ca = action {
        return ca(&paths).map(|()| ExitCode::SUCCESS);
    }
    let docker = DockerCli::from_env().map_err(|e| e.to_string())?;
    let done = |r: Res| r.map(|()| ExitCode::SUCCESS);
    match action {
        DevAction::Up { dir } => done(up::up(&docker, &paths, dir.as_deref())),
        DevAction::Ls { json } => Ok(inventory::ls(&docker, &paths, json)),
        DevAction::Down {
            project,
            volumes,
            yes,
        } => done(remove::down(&docker, &paths, &project, volumes, yes)),
        DevAction::Gc { volumes, yes } => done(remove::gc(&docker, &paths, volumes, yes)),
        DevAction::Ca => unreachable!("handled above"),
    }
}

/// A project name as plan 22 makes them (one rule: `project::check_name`).
// Used by `down` and `gc` (plan 24 Tasks 4 and 5).
pub(crate) fn valid_project(name: &str) -> bool {
    saiife_dev::project::check_name(name).is_ok()
}

const NEED_YES: &str = "deleting volumes needs a yes. Run it in a terminal, or add --yes.";

/// Asks `question` on stderr and reads the answer from `input`. `yes` skips
/// the question; with no terminal there is no one to ask, so it is an error.
/// Only `y` or `yes` (any case) is a yes; anything else, or EOF, is a no.
pub(crate) fn confirm_with(
    question: &str,
    yes: bool,
    tty: bool,
    input: &mut dyn BufRead,
) -> Result<bool, String> {
    if yes {
        return Ok(true);
    }
    if !tty {
        return Err(NEED_YES.to_string());
    }
    eprint!("{question} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    input
        .read_line(&mut line)
        .map_err(|e| format!("cannot read the answer: {e}"))?;
    let answer = line.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}

/// [`confirm_with`] on the terminal.
// Used by `down` and `gc` (plan 24 Tasks 4 and 5).
pub(crate) fn confirm(question: &str, yes: bool) -> Result<bool, String> {
    let stdin = std::io::stdin();
    let tty = stdin.is_terminal();
    confirm_with(question, yes, tty, &mut stdin.lock())
}

/// Writes `bytes` to `path` so only the user can read it: the parent dir is
/// `0700` (set even when it exists) and the file `0600` from its creation.
/// The write goes to `<path>.tmp`, then is renamed over `path`.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
        // `project::assign` creates the project dir with the default mode.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    // A leftover from a crash is replaced: `create_new` then sets the mode at
    // creation and never follows a planted link.
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let written = opts.open(&tmp).and_then(|mut f| {
        f.write_all(bytes)?;
        f.sync_all()
    });
    if let Err(e) = written.and_then(|()| fs::rename(&tmp, path)) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// `ensure_ca`, then where the certificate is and how to trust it, for the
/// OS this was built for. saiife itself never touches a trust store.
fn ca(paths: &DevPaths) -> Res {
    let ca = ensure_ca(paths).map_err(|e| e.to_string())?;
    let shown = |p: &Path| sanitize(&p.display().to_string());
    let cert = shown(&ca.cert_path);
    let key = shown(&ca.key_path);
    let dir = shown(&paths.ca_dir());
    outln!("saiife dev CA certificate: {cert}");
    outln!("saiife never adds it to a trust store. To trust it yourself:");
    if cfg!(target_os = "linux") {
        outln!("  Debian, Ubuntu:   sudo cp {cert} /usr/local/share/ca-certificates/saiife-dev.crt && sudo update-ca-certificates");
        outln!("  Fedora, Arch:     sudo trust anchor --store {cert}");
        outln!("  Chrome, Chromium: certutil -d sql:$HOME/.pki/nssdb -A -t C,, -n saiife-dev -i {cert}");
    } else if cfg!(target_os = "macos") {
        outln!("  System:           sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {cert}");
    } else if cfg!(windows) {
        outln!("  Current user:     certutil -user -addstore Root {cert}");
    }
    outln!("  Firefox:          Settings > Privacy & Security > Certificates > View Certificates > Authorities > Import");
    outln!("Node and Python keep their own lists: set NODE_EXTRA_CA_CERTS, SSL_CERT_FILE or REQUESTS_CA_BUNDLE to {cert}.");
    outln!("Keep {key} private: anyone who has it can make certificates this machine trusts.");
    outln!("To stop trusting it, remove it the same way and delete {dir}.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn ask(yes: bool, tty: bool, input: &str) -> Result<bool, String> {
        confirm_with("Delete 2 volumes?", yes, tty, &mut Cursor::new(input))
    }

    #[test]
    fn confirm_yes_flag_skips_the_prompt() {
        // Neither a terminal nor any input is needed.
        assert_eq!(ask(true, false, ""), Ok(true));
        assert_eq!(ask(true, true, "n\n"), Ok(true));
    }

    #[test]
    fn confirm_without_tty_is_an_error() {
        assert_eq!(
            ask(false, false, "y\n"),
            Err("deleting volumes needs a yes. Run it in a terminal, or add --yes.".to_string())
        );
    }

    #[test]
    fn confirm_reads_y_and_yes_only() {
        assert_eq!(ask(false, true, "y\n"), Ok(true));
        assert_eq!(ask(false, true, " YES \n"), Ok(true));
        for no in ["n\n", "\n", "yep\n", ""] {
            assert_eq!(ask(false, true, no), Ok(false), "{no:?}");
        }
    }

    #[test]
    fn valid_project_rejects_paths_and_case() {
        for ok in ["shop", "shop-2"] {
            assert!(valid_project(ok), "{ok}");
        }
        for bad in ["../x", "Shop", "", "a/b", "_tls"] {
            assert!(!valid_project(bad), "{bad:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn write_private_sets_modes() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let path = base.path().join("p").join("compose.json");
        write_private(&path, b"{}").unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(fs::read(&path).unwrap(), b"{}");
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        // An existing parent with the default mode is tightened; the file is
        // replaced, and no `.tmp` is left behind.
        fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o755)).unwrap();
        write_private(&path, b"[]").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"[]");
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        let names: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["compose.json"]);
    }
}
