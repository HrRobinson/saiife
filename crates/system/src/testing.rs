//! Test helpers: a complete locked-mode tree under a temp root, as install
//! and a first daemon start leave it, without running either. Not for
//! production use.

use crate::host::{FakeHost, Host};
use crate::layout::*;
use crate::unit::unit_text;
use saiife_policy::installed::{
    write_installed, FileKind, Installed, InstalledFile, ManagedAgent, VaultKeyMode,
    INSTALLED_VERSION,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// What the fake binary holds: a minimal static ELF with the release
/// build marker.
pub fn fake_binary() -> Vec<u8> {
    crate::binary::fake_elf(None, 0, Some(false))
}
/// What the fake Claude Code managed file holds.
pub const FAKE_CLAUDE_MANAGED: &str = "{\"hooks\":{}}\n";
/// The systemd version of the fake install.
pub const FAKE_SYSTEMD: u32 = 255;

fn sha256_hex(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

fn dir(path: &Path, mode: u32) {
    fs::create_dir_all(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
}

fn file(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
}

/// The config a fake install writes: the socket and audit dirs under
/// `root`, so nothing points at the real `/run` or `/var`.
pub fn fake_config(layout: &Layout) -> String {
    format!(
        "version = 2\nlocked = true\n\n[daemon]\nsocket_dir = {:?}\n\n[audit]\ndir = {:?}\n",
        layout.at(RUN_DIR).display().to_string(),
        layout.at(AUDIT_DIR).display().to_string(),
    )
}

/// Writes the §5.2 tree under `root` with its modes: the binary, `/etc/saiife`
/// (config, `policy.d`, credstore with an encrypted vault key), the unit,
/// the Claude Code managed file, the state, keys (with a 32-byte key), audit
/// and run dirs systemd and the daemon make, an Ubuntu 24.04 `os-release`
/// `/run/systemd/system`, and an `/etc/passwd` with root, the daemon user
/// and the calling user. The [`FakeHost`] of `root` gets the users and
/// groups (`saiife` in `saiife-audit`). Returns the `installed.toml` it
/// wrote. Panics on any error.
#[doc(hidden)]
pub fn fake_install(root: &Path) -> Installed {
    let host = FakeHost::open(root).unwrap_or_else(|e| panic!("fake host: {e}"));
    let layout = Layout::under(root);
    let l = |p: &str| layout.at(p);

    for g in [DAEMON_GROUP, AUDIT_GROUP] {
        if host.group_id(g).is_none() {
            host.create_system_group(g).unwrap();
        }
    }
    if host.user(DAEMON_USER).is_none() {
        host.create_system_user(DAEMON_USER, DAEMON_GROUP).unwrap();
    }
    host.add_to_group(DAEMON_USER, AUDIT_GROUP).unwrap();

    // The supported-system facts.
    dir(&l("/etc"), 0o755);
    file(
        &l("/etc/os-release"),
        b"ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n",
        0o644,
    );
    dir(&l("/run/systemd/system"), 0o755);
    // `/etc/passwd` with root, the calling user (copied from the machine's,
    // so `doctor` finds the caller local) and the daemon user. The fake
    // daemon user shares the caller's uid, so the caller comes first.
    let mut passwd = "root:x:0:0:root:/root:/bin/sh\n".to_string();
    let uid = rustix::process::getuid().as_raw().to_string();
    if let Some(line) = fs::read_to_string("/etc/passwd").ok().and_then(|t| {
        t.lines()
            .find(|l| l.split(':').nth(2) == Some(uid.as_str()))
            .map(str::to_string)
    }) {
        passwd.push_str(&line);
        passwd.push('\n');
    }
    let daemon = host.user(DAEMON_USER).unwrap();
    passwd.push_str(&format!(
        "{DAEMON_USER}:x:{}:{}::/nonexistent:/usr/sbin/nologin\n",
        daemon.uid, daemon.gid
    ));
    file(&l("/etc/passwd"), passwd.as_bytes(), 0o644);

    // The unit's dir as the layout's platform names it.
    let unit_dir = Path::new(layout.logical(UNIT))
        .parent()
        .and_then(Path::to_str)
        .unwrap_or("/");
    for d in [OPT_DIR, BIN_DIR, ETC_DIR, POLICY_D, unit_dir] {
        dir(&l(d), 0o755);
    }
    dir(&l(CREDSTORE), 0o700);
    dir(&l(CLAUDE_MANAGED_DIR), 0o755);

    let binary = fake_binary();
    file(&l(BINARY), &binary, 0o755);
    let config = fake_config(&layout);
    file(&l(CONFIG), config.as_bytes(), 0o644);
    let vault = b"fake encrypted credential\n";
    file(&l(VAULT_KEY), vault, 0o600);
    let unit = unit_text(FAKE_SYSTEMD);
    file(&l(UNIT), unit.as_bytes(), 0o644);
    file(&l(CLAUDE_MANAGED), FAKE_CLAUDE_MANAGED.as_bytes(), 0o644);
    // The allowlist drop-in an install writes for the fake config's policy
    // (no `allow_servers`); not on the install record.
    file(
        &l(CLAUDE_MCP),
        saiife_agents::claude::managed_mcp_settings(&[]).as_bytes(),
        0o644,
    );

    // What systemd and the first daemon start make.
    dir(&l(STATE_DIR), 0o700);
    dir(&l(KEYS_DIR), 0o700);
    file(&l(AUDIT_KEY), &[7u8; 32], 0o600);
    dir(&l(LOG_DIR), 0o755);
    dir(&l(AUDIT_DIR), 0o2750);
    dir(&l(RUN_DIR), 0o755);

    let f = |path: &str, bytes: &[u8], kind| InstalledFile {
        path: path.into(),
        sha256: (kind != FileKind::VaultKey).then(|| sha256_hex(bytes)),
        kind,
        created: true,
    };
    let installed = Installed {
        version: INSTALLED_VERSION,
        saiife: env!("CARGO_PKG_VERSION").to_string(),
        installed_at: "2026-10-22T00:00:00Z".to_string(),
        systemd: FAKE_SYSTEMD,
        vault_key: VaultKeyMode::Credential,
        users: vec![DAEMON_USER.to_string()],
        groups: vec![DAEMON_GROUP.to_string(), AUDIT_GROUP.to_string()],
        memberships: vec![saiife_policy::installed::Membership {
            user: DAEMON_USER.to_string(),
            group: AUDIT_GROUP.to_string(),
        }],
        dirs: [
            OPT_DIR,
            BIN_DIR,
            ETC_DIR,
            POLICY_D,
            CREDSTORE,
            CLAUDE_MANAGED_DIR,
        ]
        .iter()
        .map(Into::into)
        .collect(),
        files: vec![
            f(BINARY, &binary, FileKind::Binary),
            f(UNIT, unit.as_bytes(), FileKind::Unit),
            f(CONFIG, config.as_bytes(), FileKind::Config),
            f(VAULT_KEY, vault, FileKind::VaultKey),
        ],
        agents: vec![ManagedAgent {
            agent: "claude".to_string(),
            path: CLAUDE_MANAGED.into(),
            sha256: sha256_hex(FAKE_CLAUDE_MANAGED.as_bytes()),
            whole_file: true,
            created_file: true,
        }],
        auth_rights: Vec::new(),
    };
    write_installed(&l(INSTALLED), &installed).unwrap();
    installed
}

/// Gives the fake host's `root` user the uid `uid` (to test a file that is
/// "not root's").
#[doc(hidden)]
pub fn set_root_uid(host: &FakeHost, uid: u32) {
    let gid = host.group_id("root").unwrap_or(0);
    host.set(|s| {
        s.users.insert(
            "root".into(),
            crate::host::UserInfo {
                uid,
                gid,
                home: "/root".into(),
                shell: "/bin/bash".into(),
            },
        );
    });
}
