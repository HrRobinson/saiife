//! Shared setup for tests that run `saiife init` / `status` / `packs`:
//! a temp project, a temp HOME, temp data and audit dirs, and a PATH that
//! holds only fake agent binaries and (optionally) a link to the saiife
//! under test. Nothing touches the real user's directories.
#![allow(dead_code)]

#[cfg(unix)]
pub mod daemon;
#[cfg(unix)]
pub mod mcp;
#[cfg(unix)]
pub mod personal;
pub mod tmp;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

pub struct Env {
    pub project: TempDir,
    pub bin: TempDir,
    pub home: TempDir,
    pub data: TempDir,
    pub audit: TempDir,
    /// Stands in for /etc/claude-code (`SAIIFE_TEST_CLAUDE_MANAGED_DIRS`).
    pub managed: TempDir,
}

/// An executable shell script `dir/name` with `body` after the shebang. On
/// Windows an agent's script takes the name production looks for
/// (`claude.exe`, `codex.cmd`, `gemini.cmd`).
pub fn fake_exe(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(platform_name(name));
    fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    // Unix needs the executable bit. On Windows `which` accepts any file of
    // that exact name, so the script is found but never run: a test that
    // runs the script is `#[cfg(unix)]`.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    }
    p
}

/// `name` as it goes on `PATH` on this host: an agent's first name from
/// `agent_binaries`, anything else as given.
fn platform_name(name: &str) -> String {
    saiife_agents::Agent::ALL
        .into_iter()
        .find(|a| a.binary() == name)
        .and_then(|a| {
            saiife_agents::detect::agent_binaries(a, cfg!(windows))
                .into_iter()
                .next()
        })
        .unwrap_or_else(|| name.to_string())
}

/// Point every lookup of the user's profile at `home`: `HOME`, and on Windows
/// `USERPROFILE`, `LOCALAPPDATA` and `APPDATA` (ruling P4). Linux and macOS
/// ignore the last three.
pub fn set_profile(cmd: &mut Command, home: &Path) {
    cmd.env("HOME", home)
        .env("USERPROFILE", home)
        .env("LOCALAPPDATA", home.join("AppData").join("Local"))
        .env("APPDATA", home.join("AppData").join("Roaming"));
}

/// `path` canonical, as saiife prints it: on Windows without the `\\\\?\\`
/// that canonicalizing adds there.
pub fn canonical_shown(path: &Path) -> String {
    saiife_win::display::shown(&fs::canonicalize(path).unwrap())
}

impl Env {
    /// Fake `agents` on PATH plus a symlink `saiife` -> the binary under test.
    pub fn new(agents: &[&str]) -> Env {
        let env = Env::bare(agents);
        #[cfg(unix)]
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_saiife"), env.bin.path().join("saiife"))
            .unwrap();
        // Creating a symlink needs a privilege on Windows: copy the binary.
        // The copy carries the platform's executable suffix (`saiife.exe`),
        // the name production has; `which` finds it through `PATHEXT`.
        #[cfg(not(unix))]
        fs::copy(
            env!("CARGO_BIN_EXE_saiife"),
            env.bin
                .path()
                .join(format!("saiife{}", std::env::consts::EXE_SUFFIX)),
        )
        .unwrap();
        env
    }

    /// Fake `agents` on PATH and no `saiife` on PATH.
    pub fn bare(agents: &[&str]) -> Env {
        let env = Env {
            project: tmp::short_tempdir(),
            bin: tmp::short_tempdir(),
            home: tmp::short_tempdir(),
            data: tmp::short_tempdir(),
            audit: tmp::short_tempdir(),
            managed: tmp::short_tempdir(),
        };
        for a in agents {
            fake_exe(env.bin.path(), a, "exit 0");
        }
        env
    }

    pub fn root(&self) -> &Path {
        self.project.path()
    }

    /// Run the saiife under test in the project root.
    pub fn saiife(&self, args: &[&str]) -> Output {
        self.saiife_in(self.root(), args)
    }

    pub fn saiife_in(&self, dir: &Path, args: &[&str]) -> Output {
        self.command_in(dir, args).output().unwrap()
    }

    /// The saiife a test runs. `init` and `status` compare the running binary
    /// with the `saiife` on PATH. On Unix that is a symlink to the binary under
    /// test, which resolves to the same file. Windows has a copy, which does
    /// not, so the copy is what runs, as an installed saiife does. A test may
    /// have swapped the copy for a script that cannot start: then the binary
    /// under test runs, a different one from PATH's.
    pub fn exe(&self) -> PathBuf {
        #[cfg(windows)]
        {
            use std::io::Read;
            let copy = self.bin.path().join("saiife.exe");
            let mut magic = [0u8; 2];
            let real = fs::File::open(&copy).and_then(|mut f| f.read_exact(&mut magic));
            if real.is_ok() && &magic == b"MZ" {
                return copy;
            }
        }
        PathBuf::from(env!("CARGO_BIN_EXE_saiife"))
    }

    fn command_in(&self, dir: &Path, args: &[&str]) -> Command {
        let mut cmd = Command::new(self.exe());
        cmd.args(args)
            .current_dir(dir)
            .env("PATH", self.bin.path())
            .env("SAIIFE_DATA_DIR", self.data.path())
            .env("SAIIFE_AUDIT_DIR", self.audit.path())
            .env("SAIIFE_TEST_CLAUDE_MANAGED_DIRS", self.managed.path())
            .env("XDG_RUNTIME_DIR", self.no_runtime_dir());
        set_profile(&mut cmd, self.home.path());
        cmd
    }

    /// A runtime dir that does not exist, under the test HOME: no test can
    /// reach a real `$XDG_RUNTIME_DIR/saiife/saiife.sock` (plan 16).
    pub fn no_runtime_dir(&self) -> PathBuf {
        self.home.path().join("no-runtime")
    }

    /// `saiife` in the project root, killed after `limit`: `None` if it was
    /// still running then (it hung). Output is small, so the pipes are read
    /// after the exit without risk of a full-pipe deadlock.
    pub fn saiife_within(&self, args: &[&str], limit: std::time::Duration) -> Option<Output> {
        use std::process::Stdio;
        let mut child = self
            .command_in(self.root(), args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + limit;
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        Some(child.wait_with_output().unwrap())
    }

    pub fn read(&self, rel: &str) -> String {
        fs::read_to_string(self.root().join(rel)).unwrap()
    }

    pub fn write(&self, rel: &str, contents: &str) {
        let p = self.root().join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, contents).unwrap();
    }
}

pub fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

pub fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

/// Point a `saiife` command away from every real user directory: HOME and
/// the data dir go to a fresh temp dir (returned; keep it alive until the
/// child exits), the audit log to `audit`.
pub fn hermetic(cmd: &mut Command, audit: &Path) -> TempDir {
    let sandbox = tmp::short_tempdir();
    let home = sandbox.path().join("home");
    let data = sandbox.path().join("data");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&data).unwrap();
    set_profile(cmd, &home);
    cmd.env("SAIIFE_DATA_DIR", &data)
        .env("SAIIFE_AUDIT_DIR", audit);
    sandbox
}

/// A system config path that does not exist, under `dir`: `saiife audit`,
/// `audit verify` and `--report` given it are in developer mode whatever
/// the host has in /etc/saiife.
pub fn absent_system_config(dir: &Path) -> PathBuf {
    dir.join("absent-system-config.toml")
}

/// [`hermetic`] for `saiife audit <args>` (the table, `--report` and
/// `verify`): the args, then `--system-config` naming a file that does not
/// exist, so no test reads /etc/saiife. Windows refuses that flag as a locked
/// one and reads no system config in developer mode, so it goes without.
pub fn hermetic_audit<I, S>(cmd: &mut Command, audit: &Path, args: I) -> TempDir
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let sandbox = hermetic(cmd, audit);
    cmd.arg("audit").args(args);
    if cfg!(not(windows)) {
        cmd.arg("--system-config")
            .arg(absent_system_config(sandbox.path()));
    }
    sandbox
}

/// The complete lines of an audit file being written: a last line
/// without its `\n` is an append still in progress (a reader racing the
/// daemon's writer), not a record yet, and is left out.
pub fn complete_lines(text: &str) -> impl Iterator<Item = &str> {
    let end = text.rfind('\n').map_or(0, |i| i + 1);
    text[..end].lines()
}

/// The `cwd` the recorded fixtures use.
pub const FIXTURE_CWD: &str = "/home/u/app";

/// The home the recorded fixtures spell.
pub const FIXTURE_HOME: &str = "/home/u";

/// A real, canonical stand-in for `/home/u`: payloads spell `/home/u`, and
/// `real` rewrites them to a fresh temp dir (holding `app/`) before they
/// reach `saiife`, `spelled` maps the paths in the answer back. Paths under
/// `/home/u` are never resolved for real: on macOS `/home` is an autofs
/// mount, and resolving through it can stall past the latency budget.
pub struct FixtureHome {
    _dir: TempDir,
    root: String,
}

impl FixtureHome {
    pub fn new() -> FixtureHome {
        let dir = tmp::short_tempdir();
        let root = fs::canonicalize(dir.path()).unwrap().join("u");
        fs::create_dir_all(root.join("app")).unwrap();
        assert_no_host_config(&root);
        FixtureHome {
            _dir: dir,
            root: fixture_spelling(root.to_str().unwrap()),
        }
    }

    /// `s`, a shell line or a path, with the stand-in in place of `/home/u`.
    /// Under POSIX rules a backslash would be an escape, so on Windows the
    /// stand-in is spelled with `/`, which every reader takes.
    pub fn real(&self, s: &str) -> String {
        s.replace(FIXTURE_HOME, &self.root)
    }

    /// `b`, serialized JSON, with the stand-in in place of `/home/u`: its
    /// spelling holds no `\\`, so it is valid inside a JSON string as it is.
    pub fn real_bytes(&self, b: &[u8]) -> Vec<u8> {
        match std::str::from_utf8(b) {
            Ok(s) => self.real(s).into_bytes(),
            Err(_) => b.to_vec(),
        }
    }

    /// `s` from an answer or a record, with `/home/u` in place of the stand-in,
    /// however the answer spells it (Windows: `d:/x`, lower-case drive).
    pub fn spelled(&self, s: &str) -> String {
        if cfg!(not(windows)) {
            return s.replace(&self.root, FIXTURE_HOME);
        }
        let lower = self.root[..1].to_ascii_lowercase() + &self.root[1..];
        let back = self.root.replace('/', "\\");
        let mut out = s.to_string();
        for form in [
            format!(r"\\?\{back}"),
            back.clone(),
            back.replace('\\', r"\\"),
            self.root.clone(),
            lower,
        ] {
            out = out.replace(&form, FIXTURE_HOME);
        }
        out
    }

    pub fn spelled_record(&self, mut r: saiife_audit::Record) -> saiife_audit::Record {
        r.project = self.spelled(&r.project);
        if cfg!(windows) {
            r.project = r.project.replace('\\', "/");
        }
        r.input = self.spelled(&r.input);
        r.reason = r.reason.map(|x| self.spelled(&x));
        r
    }
}

/// A canonical path as JSON text and shell lines can carry it. On Windows
/// `canonicalize` gives `\\\\?\\D:\\x`: raw backslashes break the serialized JSON
/// the fixtures are rewritten in, so it becomes `D:/x`. Elsewhere it is as given.
fn fixture_spelling(path: &str) -> String {
    if cfg!(windows) {
        path.strip_prefix(r"\\?\")
            .unwrap_or(path)
            .replace('\\', "/")
    } else {
        path.to_string()
    }
}

/// `saiife check` reads the nearest `.saiife/config.toml` at or above the
/// payload's `cwd`. Fixture cwds like `/home/u/app` are not temp dirs, so a
/// project config on this host at `/home/u/app`, `/home/u`, `/home` or `/`
/// would change the packs under test: fail loudly instead of passing on
/// the host's config.
pub fn assert_no_host_config(cwd: &Path) {
    for d in cwd.ancestors() {
        let c = d.join(".saiife/config.toml");
        assert!(
            !c.exists(),
            "{} exists on this host; tests that use cwd {} would read it",
            c.display(),
            cwd.display()
        );
    }
}
