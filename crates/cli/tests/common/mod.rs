//! Shared setup for tests that run `saiife init` / `status` / `packs`:
//! a temp project, a temp HOME, temp data and audit dirs, and a PATH that
//! holds only fake agent binaries and (optionally) a link to the saiife
//! under test. Nothing touches the real user's directories.
#![allow(dead_code)]

#[cfg(target_os = "linux")]
pub mod daemon;

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

/// An executable shell script `dir/name` with `body` after the shebang.
pub fn fake_exe(dir: &Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join(name);
    fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    p
}

impl Env {
    /// Fake `agents` on PATH plus a symlink `saiife` -> the binary under test.
    pub fn new(agents: &[&str]) -> Env {
        let env = Env::bare(agents);
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_saiife"), env.bin.path().join("saiife"))
            .unwrap();
        env
    }

    /// Fake `agents` on PATH and no `saiife` on PATH.
    pub fn bare(agents: &[&str]) -> Env {
        let env = Env {
            project: daemon::short_tempdir(),
            bin: daemon::short_tempdir(),
            home: daemon::short_tempdir(),
            data: daemon::short_tempdir(),
            audit: daemon::short_tempdir(),
            managed: daemon::short_tempdir(),
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

    fn command_in(&self, dir: &Path, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_saiife"));
        cmd.args(args)
            .current_dir(dir)
            .env("PATH", self.bin.path())
            .env("HOME", self.home.path())
            .env("SAIIFE_DATA_DIR", self.data.path())
            .env("SAIIFE_AUDIT_DIR", self.audit.path())
            .env("SAIIFE_TEST_CLAUDE_MANAGED_DIRS", self.managed.path());
        cmd
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
    let sandbox = daemon::short_tempdir();
    let home = sandbox.path().join("home");
    let data = sandbox.path().join("data");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&data).unwrap();
    cmd.env("HOME", &home)
        .env("SAIIFE_DATA_DIR", &data)
        .env("SAIIFE_AUDIT_DIR", audit);
    sandbox
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
        let dir = daemon::short_tempdir();
        let root = fs::canonicalize(dir.path()).unwrap().join("u");
        fs::create_dir_all(root.join("app")).unwrap();
        assert_no_host_config(&root);
        FixtureHome {
            _dir: dir,
            root: root.to_str().unwrap().to_string(),
        }
    }

    pub fn real(&self, s: &str) -> String {
        s.replace(FIXTURE_HOME, &self.root)
    }

    pub fn real_bytes(&self, b: &[u8]) -> Vec<u8> {
        match std::str::from_utf8(b) {
            Ok(s) => self.real(s).into_bytes(),
            Err(_) => b.to_vec(),
        }
    }

    pub fn spelled(&self, s: &str) -> String {
        s.replace(&self.root, FIXTURE_HOME)
    }

    pub fn spelled_record(&self, mut r: saiife_audit::Record) -> saiife_audit::Record {
        r.project = self.spelled(&r.project);
        r.input = self.spelled(&r.input);
        r.reason = r.reason.map(|x| self.spelled(&x));
        r
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
