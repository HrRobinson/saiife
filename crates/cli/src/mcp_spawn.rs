//! `saiife __mcp-spawn` (hidden): starts one MCP gateway server for the
//! daemon, confined (plan 17, decision 12).
//!
//! It reads a [`SpawnSpec`] frame from stdin (the rest of stdin is the
//! server's), starts a new session, makes sure no descriptor above 2
//! survives the exec, clears the environment down to `PATH`, `HOME`,
//! `LANG` and the listed secrets, enters the server's home, applies
//! `no_new_privs` and the Landlock ruleset, and execs the server. Any
//! failure exits 126 with a one-line reason that holds no values.

use saiife_system::sandbox::{self, SpawnSpec};
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode};

/// The exit code of every failure, as a shell uses for "cannot execute".
pub const EXIT_SPAWN_FAILED: u8 = 126;

pub fn run() -> ExitCode {
    let reason = match spawn() {
        Ok(never) => match never {},
        Err(r) => r,
    };
    eprintln!("saiife: __mcp-spawn: {reason}");
    ExitCode::from(EXIT_SPAWN_FAILED)
}

fn spawn() -> Result<std::convert::Infallible, String> {
    let spec = sandbox::read_spec_from_stdin().map_err(|e| e.to_string())?;
    rustix::process::setsid().map_err(|_| "cannot start a new session".to_string())?;
    // std opens everything close-on-exec, so this is normally empty: a
    // descriptor someone leaked to us is closed by the shell below, which
    // can name only single-digit ones: anything higher is refused.
    let leaked =
        sandbox::inherited_fds().map_err(|_| "cannot list open descriptors".to_string())?;
    if leaked.iter().any(|&fd| fd > sandbox::MAX_CLOSABLE_FD) {
        return Err("an inherited descriptor above 9".to_string());
    }
    std::env::set_current_dir(&spec.home).map_err(|_| "cannot enter the home dir".to_string())?;
    sandbox::apply(&spec).map_err(|e| e.to_string())?;
    if spec.sandbox == sandbox::Sandbox::Landlock {
        if let Some(gap) = sandbox::sandbox_strength().gap() {
            eprintln!("saiife: __mcp-spawn: weaker sandbox: {gap}");
        }
    }
    let err = command(&spec, &leaked).exec();
    Err(format!("cannot exec the server: {}", err.kind()))
}

/// The exec. With leaked descriptors, `/bin/sh` closes them (`N<&-`) and
/// execs the server in its place: closing a descriptor we do not own takes
/// `unsafe` in Rust, a shell redirection does not.
fn command(spec: &SpawnSpec, leaked: &[i32]) -> Command {
    let mut c = if leaked.is_empty() {
        let mut c = Command::new(&spec.command);
        c.args(&spec.args);
        c
    } else {
        let closes: Vec<String> = leaked.iter().map(|fd| format!("{fd}<&-")).collect();
        let mut c = Command::new("/bin/sh");
        c.arg("-c")
            .arg(format!("exec \"$0\" \"$@\" {}", closes.join(" ")))
            .arg(&spec.command)
            .args(&spec.args);
        c
    };
    c.env_clear().envs(spec.child_env());
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use saiife_system::sandbox::Sandbox;
    use std::path::PathBuf;

    fn spec() -> SpawnSpec {
        SpawnSpec {
            command: PathBuf::from("/usr/bin/server"),
            args: vec!["--x".into(), "a b".into()],
            env: vec![],
            home: PathBuf::from("/h"),
            read_paths: vec![],
            sandbox: Sandbox::Landlock,
        }
    }

    #[test]
    fn direct_exec_without_leaks() {
        let c = command(&spec(), &[]);
        assert_eq!(c.get_program(), "/usr/bin/server");
        let args: Vec<_> = c.get_args().collect();
        assert_eq!(args, ["--x", "a b"]);
    }

    #[test]
    fn shell_closes_leaked_fds_and_keeps_args_apart() {
        let c = command(&spec(), &[3, 7]);
        assert_eq!(c.get_program(), "/bin/sh");
        let args: Vec<_> = c.get_args().collect();
        assert_eq!(
            args,
            [
                "-c",
                "exec \"$0\" \"$@\" 3<&- 7<&-",
                "/usr/bin/server",
                "--x",
                "a b"
            ]
        );
    }
}
