//! Shared setup for tests that run `saiife init` / `status` / `packs`:
//! a temp project, a temp HOME, temp data and audit dirs, and a PATH that
//! holds only fake agent binaries and (optionally) a link to the saiife
//! under test. Nothing touches the real user's directories.
#![allow(dead_code)]

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
            project: tempfile::tempdir().unwrap(),
            bin: tempfile::tempdir().unwrap(),
            home: tempfile::tempdir().unwrap(),
            data: tempfile::tempdir().unwrap(),
            audit: tempfile::tempdir().unwrap(),
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
        Command::new(env!("CARGO_BIN_EXE_saiife"))
            .args(args)
            .current_dir(dir)
            .env("PATH", self.bin.path())
            .env("HOME", self.home.path())
            .env("SAIIFE_DATA_DIR", self.data.path())
            .env("SAIIFE_AUDIT_DIR", self.audit.path())
            .output()
            .unwrap()
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
