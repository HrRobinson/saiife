//! `saiife system install --fleet` (plan 18 decision 2): the install
//! options from root-owned files that a package or an MDM tool lays down
//! under [`FLEET_DIR`]:
//!
//! - [`FLEET_CONFIG`]: the system config, passed as `--config` (so it is
//!   checked and copied to `/etc/saiife/config.toml` on every run);
//! - [`FLEET_INSTALL`]: `agents` and `approvers`, both optional.
//!   `approvers` only fills a new default config: with [`FLEET_CONFIG`]
//!   there it is refused (the approvers go in that file's
//!   `[approval] approvers`).
//!
//! The dir (and each dir above it) and both files must be root's and not
//! writable by group or others. The files must be regular files, opened
//! without following a symlink, of at most [`MAX_FLEET_FILE`] bytes.
//! Anything else is refused before install changes anything. A missing
//! [`FLEET_DIR`] means no fleet files.

use crate::fsops;
use crate::host::Host;
use crate::install::{
    check_owner_mode_for, read_previous_record, refused, InstallError, InstallOptions,
};
use crate::layout::*;
use saiife_agents::Agent;
use saiife_policy::installed::read_installed;
use serde::Deserialize;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Largest fleet file read (1 MiB).
pub const MAX_FLEET_FILE: u64 = 1024 * 1024;

/// `/etc/saiife/fleet/install.toml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetInstall {
    pub agents: Option<Vec<String>>,
    #[serde(default)]
    pub approvers: Vec<String>,
}

/// The install options the fleet files give. The agents come from
/// `install.toml` when it lists them; otherwise they are the agents
/// `installed.toml` recorded (an upgrade never adds an agent the admin
/// left out), or after a plain uninstall the agents its kept copy
/// recorded; with none of these, all of them.
///
/// Dropping an agent from `install.toml` does not remove its managed
/// hooks (install never removes them); `system uninstall` then `system
/// install --fleet` does.
pub fn fleet_options(layout: &Layout, host: &dyn Host) -> Result<InstallOptions, InstallError> {
    if layout.is_system() && host.euid() != 0 {
        return Err(InstallError::NotRoot);
    }
    let root_uid = host
        .user("root")
        .map(|u| u.uid)
        .ok_or_else(|| InstallError::Step {
            step: "fleet".into(),
            detail: "user root not found".into(),
        })?;
    let (config, install) = if fleet_dir_present(layout, host, root_uid)? {
        (
            read_fleet_file(layout, host, FLEET_CONFIG, root_uid)?,
            read_fleet_file(layout, host, FLEET_INSTALL, root_uid)?,
        )
    } else {
        (None, None)
    };
    let fleet = match install {
        Some(bytes) => parse_install(&bytes)?,
        None => FleetInstall {
            agents: None,
            approvers: Vec::new(),
        },
    };
    // The fleet config is copied as it is: approvers here would be dropped
    // without a word.
    if config.is_some() && !fleet.approvers.is_empty() {
        return Err(refused(
            Path::new(FLEET_INSTALL),
            format!(
                "approvers is not used when {FLEET_CONFIG} exists; \
                 set them as [approval] approvers in {FLEET_CONFIG} and drop approvers here"
            ),
        ));
    }
    let agents = match fleet.agents {
        Some(names) => names
            .iter()
            .map(|n| {
                Agent::from_name(n).ok_or_else(|| {
                    refused(
                        Path::new(FLEET_INSTALL),
                        format!("unknown agent {n:?} (claude, codex, gemini)"),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        None => recorded_agents(layout, host)?.unwrap_or_else(|| Agent::ALL.to_vec()),
    };
    Ok(InstallOptions {
        config: config.map(|_| layout.at(FLEET_CONFIG)),
        agents,
        approvers: fleet.approvers,
        non_interactive: true,
        allow_test_build: false,
    })
}

fn parse_install(bytes: &[u8]) -> Result<FleetInstall, InstallError> {
    let p = Path::new(FLEET_INSTALL);
    let text = std::str::from_utf8(bytes).map_err(|e| refused(p, format!("not UTF-8: {e}")))?;
    toml::from_str(text).map_err(|e| refused(p, e.message().to_string()))
}

/// The agents an earlier install recorded (an empty list stays empty):
/// `installed.toml`, else the copy a plain uninstall kept (so removing and
/// reinstalling the package keeps the admin's choice); `None` without
/// either.
fn recorded_agents(layout: &Layout, host: &dyn Host) -> Result<Option<Vec<Agent>>, InstallError> {
    let rec =
        read_installed(&layout.at(INSTALLED)).map_err(|e| refused(Path::new(INSTALLED), e))?;
    let rec = rec.or_else(|| read_previous_record(layout, host));
    Ok(rec.map(|i| {
        i.agents
            .iter()
            .filter_map(|a| Agent::from_name(&a.agent))
            .collect()
    }))
}

/// Walks every dir down to [`FLEET_DIR`]: each must be a directory (not a
/// symlink) of root's, not writable by group or others; a sticky bit does
/// not excuse a writable one. False when one is missing (no fleet files).
fn fleet_dir_present(
    layout: &Layout,
    host: &dyn Host,
    root_uid: u32,
) -> Result<bool, InstallError> {
    let mut logical = PathBuf::from("/");
    for comp in Path::new(FLEET_DIR).components().skip(1) {
        logical.push(comp);
        let p = layout
            .try_at(&logical)
            .map_err(|e| refused(&logical, e.to_string()))?;
        let m = match fsops::lstat(&p) {
            Ok(None) => return Ok(false),
            Ok(Some(m)) => m,
            Err(e) => return Err(refused(&logical, e.to_string())),
        };
        if !m.is_dir() {
            return Err(refused(&logical, "is not a directory"));
        }
        check_owner_mode_for(
            &logical,
            host.owner_uid(&p, m.uid()),
            m.mode() & 0o777,
            root_uid,
            "saiife does not read fleet files below it",
        )?;
    }
    Ok(true)
}

/// The fleet file `abs`, read through one `O_NOFOLLOW` open: it must be a
/// regular file of root's, not writable by group or others (checked on
/// that open file), of at most [`MAX_FLEET_FILE`] bytes. `None` when it
/// does not exist.
fn read_fleet_file(
    layout: &Layout,
    host: &dyn Host,
    abs: &str,
    root_uid: u32,
) -> Result<Option<Vec<u8>>, InstallError> {
    use rustix::fs::{Mode, OFlags};
    use rustix::io::Errno;
    let logical = Path::new(abs);
    let p = layout.at(abs);
    let fd = match rustix::fs::open(
        &p,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(Errno::LOOP) => {
            return Err(refused(
                logical,
                "is a symlink; fleet files must be regular files",
            ))
        }
        Err(e) => return Err(refused(logical, format!("cannot open: {e}"))),
    };
    let f = std::fs::File::from(fd);
    let m = f
        .metadata()
        .map_err(|e| refused(logical, format!("cannot stat: {e}")))?;
    if !m.is_file() {
        return Err(refused(
            logical,
            "is not a regular file; fleet files must be regular files",
        ));
    }
    // The sticky bit means nothing on a file: it never excuses a
    // group- or world-writable one.
    check_owner_mode_for(
        logical,
        host.owner_uid(&p, m.uid()),
        m.mode() & 0o777,
        root_uid,
        "saiife does not use it",
    )?;
    let too_large = || refused(logical, "is larger than 1 MiB; saiife does not use it");
    if m.len() > MAX_FLEET_FILE {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    // Bounded even when the file grows after the size check.
    f.take(MAX_FLEET_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| refused(logical, format!("cannot read: {e}")))?;
    if bytes.len() as u64 > MAX_FLEET_FILE {
        return Err(too_large());
    }
    Ok(Some(bytes))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::install::tests::{all_agents, env, Env};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    const CONFIG_TEXT: &str = "version = 2\nlocked = true\n";

    fn fleet_dir(e: &Env) {
        fs::create_dir_all(e.at(FLEET_DIR)).unwrap();
        for d in ["/etc", ETC_DIR, FLEET_DIR] {
            fs::set_permissions(e.at(d), fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    fn put(e: &Env, abs: &str, bytes: &[u8]) {
        fleet_dir(e);
        fs::write(e.at(abs), bytes).unwrap();
        fs::set_permissions(e.at(abs), fs::Permissions::from_mode(0o644)).unwrap();
    }

    fn refusal(e: &Env) -> (PathBuf, String) {
        match fleet_options(&e.layout, &e.host) {
            Err(InstallError::Refused { path, detail }) => (path, detail),
            Err(other) => panic!("{other:?}"),
            Ok(o) => panic!("accepted: {:?} {:?}", o.config, o.agents),
        }
    }

    #[test]
    fn fleet_reads_config_and_agents() {
        let e = env(255);
        put(&e, FLEET_CONFIG, CONFIG_TEXT.as_bytes());
        put(&e, FLEET_INSTALL, b"agents = [\"claude\", \"codex\"]\n");
        let opts = fleet_options(&e.layout, &e.host).unwrap();
        assert_eq!(opts.agents, [Agent::Claude, Agent::Codex]);
        assert_eq!(
            opts.config,
            Some(e.layout.root().join("etc/saiife/fleet/config.toml"))
        );
        assert!(opts.approvers.is_empty());
        assert!(opts.non_interactive);
        assert!(!opts.allow_test_build);
    }

    #[test]
    fn fleet_approvers_with_a_fleet_config_refused() {
        let e = env(255);
        put(&e, FLEET_CONFIG, CONFIG_TEXT.as_bytes());
        put(&e, FLEET_INSTALL, b"approvers = [\"group:ops\"]\n");
        let (path, detail) = refusal(&e);
        assert_eq!(path, Path::new(FLEET_INSTALL));
        assert!(
            detail.contains("[approval] approvers in /etc/saiife/fleet/config.toml"),
            "{detail}"
        );
        // An empty list is no conflict.
        put(&e, FLEET_INSTALL, b"approvers = []\n");
        assert!(fleet_options(&e.layout, &e.host).is_ok());
        // Without the fleet config, approvers fill a new default config.
        fs::remove_file(e.at(FLEET_CONFIG)).unwrap();
        put(&e, FLEET_INSTALL, b"approvers = [\"group:ops\"]\n");
        let opts = fleet_options(&e.layout, &e.host).unwrap();
        assert_eq!(opts.approvers, ["group:ops"]);
    }

    #[test]
    fn fleet_after_plain_uninstall_uses_the_kept_agents() {
        let e = env(255);
        let mut o = all_agents();
        o.agents = vec![Agent::Codex];
        e.run(&o).unwrap();
        crate::uninstall::uninstall(
            &e.layout,
            &e.host,
            &crate::uninstall::UninstallOptions { purge: false },
        )
        .unwrap();
        assert!(!e.at(INSTALLED).exists());
        assert!(e.at(crate::install::PREVIOUS).is_file());
        let opts = fleet_options(&e.layout, &e.host).unwrap();
        assert_eq!(opts.agents, [Agent::Codex]);
        // A copy that is not 0600 is not trusted: all agents.
        fs::set_permissions(
            e.at(crate::install::PREVIOUS),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let opts = fleet_options(&e.layout, &e.host).unwrap();
        assert_eq!(opts.agents, Agent::ALL);
    }

    #[test]
    fn fleet_without_files_uses_recorded_agents() {
        let e = env(255);
        let mut o = all_agents();
        o.agents = vec![Agent::Claude];
        e.run(&o).unwrap();
        assert!(!e.at(FLEET_DIR).exists());
        let opts = fleet_options(&e.layout, &e.host).unwrap();
        assert_eq!(opts.agents, [Agent::Claude]);
        assert_eq!(opts.config, None);
        // An empty fleet dir is the same.
        fleet_dir(&e);
        let opts = fleet_options(&e.layout, &e.host).unwrap();
        assert_eq!(opts.agents, [Agent::Claude]);
        // install.toml without agents too.
        put(&e, FLEET_INSTALL, b"approvers = [\"alice\"]\n");
        let opts = fleet_options(&e.layout, &e.host).unwrap();
        assert_eq!(opts.agents, [Agent::Claude]);
        assert_eq!(opts.approvers, ["alice"]);
    }

    #[test]
    fn fleet_without_anything_defaults_to_all_agents() {
        let e = env(255);
        let opts = fleet_options(&e.layout, &e.host).unwrap();
        assert_eq!(opts.agents, Agent::ALL);
        assert_eq!(opts.config, None);
        assert!(opts.approvers.is_empty());
        assert!(opts.non_interactive);
    }

    #[test]
    fn fleet_dir_group_writable_refused() {
        let e = env(255);
        put(&e, FLEET_CONFIG, CONFIG_TEXT.as_bytes());
        fs::set_permissions(e.at(FLEET_DIR), fs::Permissions::from_mode(0o775)).unwrap();
        let (path, detail) = refusal(&e);
        assert_eq!(path, Path::new("/etc/saiife/fleet"));
        assert!(detail.contains("0775"), "{detail}");
        // A writable dir above it is refused too.
        fs::set_permissions(e.at(FLEET_DIR), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(e.at(ETC_DIR), fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(refusal(&e).0, Path::new("/etc/saiife"));
    }

    #[test]
    fn fleet_dir_sticky_world_writable_refused() {
        let e = env(255);
        put(&e, FLEET_CONFIG, CONFIG_TEXT.as_bytes());
        fs::set_permissions(e.at(FLEET_DIR), fs::Permissions::from_mode(0o1777)).unwrap();
        let (path, detail) = refusal(&e);
        assert_eq!(path, Path::new(FLEET_DIR));
        assert!(detail.contains("writable by group or others"), "{detail}");
    }

    #[test]
    fn fleet_keeps_an_empty_agents_record() {
        let e = env(255);
        let mut o = all_agents();
        o.agents = Vec::new();
        e.run(&o).unwrap();
        assert!(e.installed().agents.is_empty());
        let opts = fleet_options(&e.layout, &e.host).unwrap();
        assert!(opts.agents.is_empty(), "{:?}", opts.agents);
        // With install.toml listing agents, those win.
        put(&e, FLEET_INSTALL, b"agents = [\"gemini\"]\n");
        let opts = fleet_options(&e.layout, &e.host).unwrap();
        assert_eq!(opts.agents, [Agent::Gemini]);
    }

    #[test]
    fn fleet_file_not_root_owned_refused() {
        let e = env(255);
        put(&e, FLEET_INSTALL, b"agents = [\"claude\"]\n");
        let uid = e.host.user("root").unwrap().uid;
        e.host.chown(&e.at(FLEET_INSTALL), uid + 1, 0).unwrap();
        let (path, detail) = refusal(&e);
        assert_eq!(path, Path::new(FLEET_INSTALL));
        assert!(detail.contains("not root"), "{detail}");
        // A group-writable file is refused.
        let e = env(255);
        put(&e, FLEET_CONFIG, CONFIG_TEXT.as_bytes());
        fs::set_permissions(e.at(FLEET_CONFIG), fs::Permissions::from_mode(0o1664)).unwrap();
        let (path, detail) = refusal(&e);
        assert_eq!(path, Path::new(FLEET_CONFIG));
        assert!(detail.contains("writable"), "{detail}");
    }

    #[test]
    fn fleet_symlink_refused() {
        let e = env(255);
        fleet_dir(&e);
        let target = e.src.path().join("user-config.toml");
        fs::write(&target, CONFIG_TEXT).unwrap();
        std::os::unix::fs::symlink(&target, e.at(FLEET_CONFIG)).unwrap();
        let (path, detail) = refusal(&e);
        assert_eq!(path, Path::new(FLEET_CONFIG));
        assert!(detail.contains("symlink"), "{detail}");
        // A symlinked fleet dir is refused too.
        let e = env(255);
        fs::create_dir_all(e.at(ETC_DIR)).unwrap();
        let other = e.src.path().join("fleet");
        fs::create_dir(&other).unwrap();
        std::os::unix::fs::symlink(&other, e.at(FLEET_DIR)).unwrap();
        assert_eq!(refusal(&e).0, Path::new(FLEET_DIR));
        // A directory where a file should be.
        let e = env(255);
        fleet_dir(&e);
        fs::create_dir(e.at(FLEET_INSTALL)).unwrap();
        let (path, detail) = refusal(&e);
        assert_eq!(path, Path::new(FLEET_INSTALL));
        assert!(detail.contains("regular file"), "{detail}");
    }

    #[test]
    fn fleet_file_over_1_mib_refused() {
        let e = env(255);
        let mut big = CONFIG_TEXT.as_bytes().to_vec();
        big.resize(MAX_FLEET_FILE as usize + 1, b'\n');
        put(&e, FLEET_CONFIG, &big);
        let (path, detail) = refusal(&e);
        assert_eq!(path, Path::new(FLEET_CONFIG));
        assert!(detail.contains("1 MiB"), "{detail}");
        // Exactly 1 MiB is accepted.
        big.truncate(MAX_FLEET_FILE as usize);
        put(&e, FLEET_CONFIG, &big);
        assert!(fleet_options(&e.layout, &e.host).is_ok());
    }

    #[test]
    fn fleet_install_toml_unknown_key_refused() {
        let e = env(255);
        put(&e, FLEET_INSTALL, b"agent = [\"claude\"]\n");
        let (path, detail) = refusal(&e);
        assert_eq!(path, Path::new(FLEET_INSTALL));
        assert!(detail.contains("agent"), "{detail}");
        assert!(detail.contains("unknown field"), "{detail}");
    }

    #[test]
    fn fleet_unknown_agent_refused() {
        let e = env(255);
        put(&e, FLEET_INSTALL, b"agents = [\"claude\", \"x\"]\n");
        let (path, detail) = refusal(&e);
        assert_eq!(path, Path::new(FLEET_INSTALL));
        assert_eq!(detail, "unknown agent \"x\" (claude, codex, gemini)");
    }

    #[test]
    fn fleet_install_writes_the_fleet_config_and_only_its_agents() {
        let e = env(255);
        put(&e, FLEET_CONFIG, CONFIG_TEXT.as_bytes());
        put(&e, FLEET_INSTALL, b"agents = [\"codex\"]\n");
        let opts = fleet_options(&e.layout, &e.host).unwrap();
        e.run(&opts).unwrap();
        assert_eq!(fs::read_to_string(e.at(CONFIG)).unwrap(), CONFIG_TEXT);
        assert!(e.at(CODEX_REQUIREMENTS).is_file());
        assert!(!e.at(CLAUDE_MANAGED).exists());
        assert!(!e.at(GEMINI_SETTINGS).exists());
    }
}
