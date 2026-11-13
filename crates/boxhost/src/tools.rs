//! Host tools the driver runs, with debug-only env overrides (V9).

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Ch,
    QemuImg,
    Mke2fs,
    Gpgv,
    Curl,
    Passt,
    MkfsVfat,
    Mcopy,
    Git,
}

#[derive(Debug, Clone)]
pub struct Tools {
    paths: Vec<(Tool, PathBuf)>,
}

#[derive(Debug)]
pub enum ToolError {
    Missing {
        tool: Tool,
        path: PathBuf,
    },
    Failed {
        tool: Tool,
        status: Option<i32>,
        stderr: String,
    },
    Timeout {
        tool: Tool,
        secs: u64,
    },
    Io(io::Error),
}

const ALL: [(Tool, &str, &str); 9] = [
    (Tool::Ch, "SAIIFE_TOOL_CH", "cloud-hypervisor"),
    (Tool::QemuImg, "SAIIFE_TOOL_QEMU_IMG", "qemu-img"),
    (Tool::Mke2fs, "SAIIFE_TOOL_MKE2FS", "mke2fs"),
    (Tool::Gpgv, "SAIIFE_TOOL_GPGV", "gpgv"),
    (Tool::Curl, "SAIIFE_TOOL_CURL", "curl"),
    (Tool::Passt, "SAIIFE_TOOL_PASST", "passt"),
    (Tool::MkfsVfat, "SAIIFE_TOOL_MKFS_VFAT", "mkfs.vfat"),
    (Tool::Mcopy, "SAIIFE_TOOL_MCOPY", "mcopy"),
    (Tool::Git, "SAIIFE_TOOL_GIT", "git"),
];

const STDERR_CAP: usize = 4096;

fn cut(bytes: &[u8]) -> String {
    let more = bytes.len() > STDERR_CAP;
    let mut s = String::from_utf8_lossy(&bytes[..bytes.len().min(STDERR_CAP)]).into_owned();
    if more {
        s.push_str("...");
    }
    s
}

fn drain<R: io::Read + Send + 'static>(mut r: R) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = r.read_to_end(&mut v);
        v
    })
}

impl Tools {
    pub fn system(vmm_dir: &Path) -> Tools {
        let paths = ALL
            .iter()
            .map(|(t, _, name)| {
                let p = if *t == Tool::Ch {
                    vmm_dir.join(name)
                } else {
                    Path::new("/usr/bin").join(name)
                };
                (*t, p)
            })
            .collect();
        Tools { paths }
    }

    /// Apply `SAIIFE_TOOL_<NAME>` overrides. Debug builds only (V9): release
    /// builds ignore `env` entirely.
    pub fn with_env(mut self, env: &dyn Fn(&str) -> Option<OsString>) -> Tools {
        if !cfg!(debug_assertions) {
            return self;
        }
        for (t, var, _) in ALL {
            if let Some(v) = env(var).filter(|v| !v.is_empty()) {
                self.set(t, PathBuf::from(v));
            }
        }
        self
    }

    /// Every path through `f` (doctor re-roots them under its layout).
    pub fn map_paths(mut self, f: &dyn Fn(&Path) -> PathBuf) -> Tools {
        for e in &mut self.paths {
            e.1 = f(&e.1);
        }
        self
    }

    pub fn path(&self, t: Tool) -> &Path {
        self.paths
            .iter()
            .find(|(k, _)| *k == t)
            .map(|(_, p)| p.as_path())
            .expect("every Tool has a path")
    }

    fn set(&mut self, t: Tool, p: PathBuf) {
        if let Some(e) = self.paths.iter_mut().find(|(k, _)| *k == t) {
            e.1 = p;
        }
    }

    /// Run a tool with a cleared environment (PATH=/usr/bin:/bin,
    /// LANG=C.UTF-8) and null stdin. A non-zero exit is `Failed`.
    pub fn run(
        &self,
        t: Tool,
        args: &[&OsStr],
        timeout: Duration,
    ) -> Result<std::process::Output, ToolError> {
        let path = self.path(t);
        if !path.exists() {
            return Err(ToolError::Missing {
                tool: t,
                path: path.to_path_buf(),
            });
        }
        let mut child = Command::new(path)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(ToolError::Io)?;
        let out = child.stdout.take().map(drain);
        let err = child.stderr.take().map(drain);
        let deadline = Instant::now() + timeout;
        let status = loop {
            match child.try_wait().map_err(ToolError::Io)? {
                Some(s) => break s,
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    // The reader threads end when the pipes close; a
                    // grandchild may hold them, so they are not joined.
                    return Err(ToolError::Timeout {
                        tool: t,
                        secs: timeout.as_secs(),
                    });
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        };
        let stdout = out
            .map(|h| h.join().unwrap_or_default())
            .unwrap_or_default();
        let stderr = err
            .map(|h| h.join().unwrap_or_default())
            .unwrap_or_default();
        if !status.success() {
            return Err(ToolError::Failed {
                tool: t,
                status: status.code(),
                stderr: cut(&stderr),
            });
        }
        Ok(std::process::Output {
            status,
            stdout,
            stderr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_paths() {
        let t = Tools::system(Path::new("/v"));
        assert_eq!(t.path(Tool::Ch), Path::new("/v/cloud-hypervisor"));
        assert_eq!(t.path(Tool::QemuImg), Path::new("/usr/bin/qemu-img"));
        assert_eq!(t.path(Tool::Mke2fs), Path::new("/usr/bin/mke2fs"));
        assert_eq!(t.path(Tool::Gpgv), Path::new("/usr/bin/gpgv"));
        assert_eq!(t.path(Tool::Curl), Path::new("/usr/bin/curl"));
        assert_eq!(t.path(Tool::Passt), Path::new("/usr/bin/passt"));
        assert_eq!(t.path(Tool::MkfsVfat), Path::new("/usr/bin/mkfs.vfat"));
        assert_eq!(t.path(Tool::Mcopy), Path::new("/usr/bin/mcopy"));
        assert_eq!(t.path(Tool::Git), Path::new("/usr/bin/git"));
    }

    #[test]
    fn map_paths_reroots_every_tool() {
        let t = Tools::system(Path::new("/v"))
            .map_paths(&|p| Path::new("/r").join(p.strip_prefix("/").unwrap()));
        assert_eq!(t.path(Tool::Ch), Path::new("/r/v/cloud-hypervisor"));
        assert_eq!(t.path(Tool::Mke2fs), Path::new("/r/usr/bin/mke2fs"));
    }

    #[test]
    fn env_override_is_debug_only() {
        let env = |k: &str| (k == "SAIIFE_TOOL_QEMU_IMG").then(|| OsString::from("/x/qi"));
        let t = Tools::system(Path::new("/v")).with_env(&env);
        let want = if cfg!(debug_assertions) {
            "/x/qi"
        } else {
            "/usr/bin/qemu-img"
        };
        assert_eq!(t.path(Tool::QemuImg), Path::new(want));
        assert_eq!(t.path(Tool::Git), Path::new("/usr/bin/git"));
    }

    #[cfg(unix)]
    fn script(dir: &Path, body: &str) -> Tools {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("tool.sh");
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut t = Tools::system(dir);
        t.set(Tool::Git, p);
        t
    }

    /// `t.run`, again while the just-written script is busy (ETXTBSY: a
    /// child another test thread forked meanwhile still holds the write
    /// fd until its exec).
    #[cfg(unix)]
    fn run(t: &Tools, tool: Tool, limit: Duration) -> Result<std::process::Output, ToolError> {
        for _ in 0..50 {
            match t.run(tool, &[], limit) {
                Err(ToolError::Io(e)) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                r => return r,
            }
        }
        t.run(tool, &[], limit)
    }

    #[cfg(unix)]
    #[test]
    fn run_times_out_and_kills_own_child() {
        let d = tempfile::tempdir().unwrap();
        let t = script(d.path(), "exec sleep 30");
        let start = std::time::Instant::now();
        let r = run(&t, Tool::Git, Duration::from_secs(1));
        assert!(
            matches!(
                r,
                Err(ToolError::Timeout {
                    tool: Tool::Git,
                    secs: 1
                })
            ),
            "{r:?}"
        );
        assert!(start.elapsed() < Duration::from_secs(3));
    }

    #[cfg(unix)]
    #[test]
    fn run_reports_stderr() {
        let d = tempfile::tempdir().unwrap();
        let t = script(d.path(), "echo boom >&2; exit 3");
        match run(&t, Tool::Git, Duration::from_secs(5)) {
            Err(ToolError::Failed {
                status: Some(3),
                stderr,
                ..
            }) => assert!(stderr.contains("boom")),
            other => panic!("{other:?}"),
        }
        let t = script(d.path(), "echo hi");
        let out = run(&t, Tool::Git, Duration::from_secs(5)).unwrap();
        assert_eq!(out.stdout, b"hi\n");
    }

    #[test]
    fn run_missing_tool() {
        let t = Tools::system(Path::new("/nonexistent-p35"));
        assert!(matches!(
            t.run(Tool::Ch, &[], Duration::from_secs(1)),
            Err(ToolError::Missing { .. })
        ));
    }
}
