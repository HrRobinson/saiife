//! `/etc/saiife/installed.toml`: what `saiife system install` created, with
//! SHA-256 fingerprints (spec §5.2). `uninstall` removes exactly what it
//! lists, `doctor` compares the files against it, and the managed hook reads
//! it to learn which agents are locked. No tokio: the hook path links this.

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// The format version written to `version`.
pub const INSTALLED_VERSION: u32 = 1;

/// Largest `installed.toml` read.
const MAX_BYTES: u64 = 1024 * 1024;

/// How the daemon gets the vault key (§5.2, builder's call 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VaultKeyMode {
    /// systemd ≥ 250: an encrypted credential (`LoadCredentialEncrypted=`).
    Credential,
    /// systemd < 250: a plain key file, root:saiife 0640 (`LoadCredential=`).
    File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    Binary,
    Unit,
    Config,
    VaultKey,
    Managed,
    /// The polkit action file (`com.saiife.approve`).
    Polkit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledFile {
    pub path: PathBuf,
    /// SHA-256 of the file. `None` for the vault key: installed.toml is
    /// world-readable, so it holds no digest of a secret, and doctor checks
    /// the key's existence, owner and mode instead. Also `None` while a
    /// write is in progress (the entry is recorded before the write).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub kind: FileKind,
    /// The file did not exist before install.
    pub created: bool,
}

/// A managed agent config saiife wrote. For a whole file (Claude's drop-in),
/// `sha256` covers the file; for an entry in a shared file (Codex, Gemini
/// CLI), it is the entry fingerprint (§8.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedAgent {
    pub agent: String,
    pub path: PathBuf,
    pub sha256: String,
    pub whole_file: bool,
    /// The file did not exist before install.
    pub created_file: bool,
}

/// `user` was added to the supplementary group `group`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Membership {
    pub user: String,
    pub group: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Installed {
    pub version: u32,
    /// The saiife version that installed.
    pub saiife: String,
    /// RFC 3339 time of the install.
    pub installed_at: String,
    pub systemd: u32,
    pub vault_key: VaultKeyMode,
    /// Only what install created, in creation order.
    pub users: Vec<String>,
    /// Only what install created, in creation order.
    pub groups: Vec<String>,
    /// Supplementary group memberships install added (`saiife` in
    /// `saiife-audit`), only when install created the user or the group, so
    /// the membership is known to be new.
    #[serde(default)]
    pub memberships: Vec<Membership>,
    /// Only what install created, in creation order.
    pub dirs: Vec<PathBuf>,
    pub files: Vec<InstalledFile>,
    pub agents: Vec<ManagedAgent>,
}

impl Installed {
    /// True when install wrote a managed config for the agent named `agent`
    /// (`claude`, `codex`, `gemini`).
    pub fn has_managed(&self, agent: &str) -> bool {
        self.agents.iter().any(|a| a.agent == agent)
    }
}

/// Reads `installed.toml`. `Ok(None)` when it does not exist. The open does
/// not follow a symlink and does not block (a FIFO cannot hang the hook);
/// only a regular file of at most 1 MiB is read.
pub fn read_installed(path: &Path) -> Result<Option<Installed>, String> {
    let shown = path.display();
    let not_regular = || format!("{shown}: not a regular file (symlinks are not followed)");
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_NOFOLLOW);
    }
    let file = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err(not_regular()),
        Err(e) => return Err(format!("{shown}: {e}")),
    };
    let meta = file.metadata().map_err(|e| format!("{shown}: {e}"))?;
    if !meta.is_file() {
        return Err(not_regular());
    }
    let too_big = || format!("{shown}: larger than 1 MiB");
    if meta.len() > MAX_BYTES {
        return Err(too_big());
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{shown}: {e}"))?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(too_big());
    }
    let text = String::from_utf8(bytes).map_err(|_| format!("{shown}: not valid UTF-8"))?;
    let installed: Installed =
        toml::from_str(&text).map_err(|e| format!("{shown}: {}", e.message()))?;
    if installed.version != INSTALLED_VERSION {
        return Err(format!(
            "{shown}: version {} is not supported (this saiife reads version {INSTALLED_VERSION})",
            installed.version
        ));
    }
    Ok(Some(installed))
}

/// `.<name>.tmp.<16 random hex>` next to `path`: not guessable, so another
/// user cannot plant it in advance (it is also opened `O_EXCL`).
fn temp_path(path: &Path) -> io::Result<PathBuf> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    let mut rnd = [0u8; 8];
    getrandom::fill(&mut rnd).map_err(|e| io::Error::other(e.to_string()))?;
    let hex: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(format!(".tmp.{hex}"));
    Ok(dir.join(tmp_name))
}

/// Writes `installed.toml`: a temp file next to it at mode 0644, synced,
/// then renamed over it (and the directory synced), so a reader sees the
/// old list or the new one, never a torn one.
pub fn write_installed(path: &Path, i: &Installed) -> io::Result<()> {
    let text = toml::to_string(i).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let tmp = temp_path(path)?;
    let result = (|| {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o644).custom_flags(libc::O_NOFOLLOW);
        }
        let mut f = opts.open(&tmp)?;
        #[cfg(unix)]
        {
            // The umask may have cleared bits; set the mode on the handle.
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        }
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result?;
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn sample() -> Installed {
        Installed {
            version: INSTALLED_VERSION,
            saiife: "0.1.1".into(),
            installed_at: "2026-10-22T10:00:00Z".into(),
            systemd: 249,
            vault_key: VaultKeyMode::File,
            users: vec!["saiife".into()],
            groups: vec!["saiife".into(), "saiife-audit".into()],
            memberships: vec![Membership {
                user: "saiife".into(),
                group: "saiife-audit".into(),
            }],
            dirs: vec!["/opt/saiife".into(), "/opt/saiife/bin".into()],
            files: vec![
                InstalledFile {
                    path: "/opt/saiife/bin/saiife".into(),
                    sha256: Some("aa".repeat(32)),
                    kind: FileKind::Binary,
                    created: true,
                },
                InstalledFile {
                    path: "/etc/saiife/credstore/vault-key".into(),
                    sha256: None,
                    kind: FileKind::VaultKey,
                    created: true,
                },
            ],
            agents: vec![
                ManagedAgent {
                    agent: "claude".into(),
                    path: "/etc/claude-code/managed-settings.d/50-saiife.json".into(),
                    sha256: "cc".repeat(32),
                    whole_file: true,
                    created_file: true,
                },
                ManagedAgent {
                    agent: "codex".into(),
                    path: "/etc/codex/requirements.toml".into(),
                    sha256: "dd".repeat(32),
                    whole_file: false,
                    created_file: false,
                },
            ],
        }
    }

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("installed.toml");
        let i = sample();
        write_installed(&p, &i).unwrap();
        assert_eq!(read_installed(&p).unwrap(), Some(i));
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("vault_key = \"file\""), "{text}");
        assert!(text.contains("kind = \"vault_key\""), "{text}");
        assert!(text.contains("[[memberships]]"), "{text}");
        // No digest of the vault key in the world-readable file.
        assert_eq!(text.matches("sha256").count(), 3, "{text}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o7777;
            assert_eq!(mode, 0o644);
        }
        // No temp file is left next to it.
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("installed.toml")]);
    }

    #[test]
    fn temp_names_are_random() {
        let p = Path::new("/etc/saiife/installed.toml");
        let a = temp_path(p).unwrap();
        let b = temp_path(p).unwrap();
        assert_ne!(a, b);
        assert_eq!(a.parent(), Some(Path::new("/etc/saiife")));
        let name = a.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with(".installed.toml.tmp."), "{name}");
        assert!(!name.ends_with(&std::process::id().to_string()), "{name}");
    }

    #[test]
    fn missing_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_installed(&dir.path().join("nope.toml")).unwrap(), None);
    }

    #[test]
    fn unknown_key_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("installed.toml");
        write_installed(&p, &sample()).unwrap();
        let mut text = std::fs::read_to_string(&p).unwrap();
        text.insert_str(0, "surprise = 1\n");
        std::fs::write(&p, text).unwrap();
        let err = read_installed(&p).unwrap_err();
        assert!(err.contains("surprise"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_refused() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.toml");
        write_installed(&real, &sample()).unwrap();
        let link = dir.path().join("installed.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = read_installed(&link).unwrap_err();
        assert!(err.contains("not a regular file"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn fifo_does_not_block() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("installed.toml");
        assert!(std::process::Command::new("mkfifo")
            .arg(&p)
            .status()
            .unwrap()
            .success());
        let start = Instant::now();
        let r = read_installed(&p);
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(r.is_err(), "{r:?}");
    }

    #[test]
    fn has_managed_by_agent_name() {
        let i = sample();
        assert!(i.has_managed("claude"));
        assert!(i.has_managed("codex"));
        assert!(!i.has_managed("gemini"));
        assert!(!i.has_managed("Claude"));
    }
}
