//! `saiife system uninstall` (spec §7): removes exactly what
//! `installed.toml` lists. The config, vault key, state, audit, users and
//! groups are kept unless `--purge`. Listed paths that are gone are
//! skipped; unlisted paths are never touched.

use crate::fsops;
use crate::host::Host;
use crate::install::{step, InstallError};
use crate::layout::*;
use saiife_agents::{codex, gemini, AgentError, Change};
use saiife_policy::installed::{read_installed, FileKind};
use std::path::{Path, PathBuf};

pub struct UninstallOptions {
    pub purge: bool,
}

/// Removes what install listed. Returns one line per thing done (and
/// `warning: …` lines), in order.
pub fn uninstall(
    layout: &Layout,
    host: &dyn Host,
    opts: &UninstallOptions,
) -> Result<Vec<String>, InstallError> {
    if layout.is_system() && host.euid() != 0 {
        return Err(InstallError::NotRoot);
    }
    let installed_path = layout.at(INSTALLED);
    // 1. Nothing listed, nothing to do.
    let Some(rec) = read_installed(&installed_path).map_err(|e| InstallError::Refused {
        path: installed_path.clone(),
        detail: e,
    })?
    else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    let at = |p: &Path| -> Result<PathBuf, InstallError> {
        layout.try_at(p).map_err(|e| InstallError::Refused {
            path: installed_path.clone(),
            detail: e.to_string(),
        })
    };

    // 2. Stop the daemon; a failure is only a warning.
    systemctl_warn(host, &["disable", "--now", UNIT_NAME], &mut out);

    // 3. Managed agent configs.
    for a in rec.agents.iter().rev() {
        let p = at(&a.path)?;
        let shown = a.path.display();
        if a.whole_file {
            let Some(sha) = fsops::sha256_file(&p).map_err(step("managed"))? else {
                continue;
            };
            fsops::remove_if_listed(&p).map_err(step("managed"))?;
            out.push(if sha == a.sha256 {
                format!("removed {shown}")
            } else {
                format!("removed {shown} (changed since install)")
            });
            continue;
        }
        let remove: fn(&Path) -> Result<Change, AgentError> = match a.agent.as_str() {
            "codex" => codex::remove_managed,
            "gemini" => gemini::remove_managed,
            other => {
                out.push(format!(
                    "warning: unknown managed agent {other:?} in installed.toml; {shown} left as is"
                ));
                continue;
            }
        };
        if fsops::lstat(&p).map_err(step("managed"))?.is_none() {
            continue;
        }
        let changed = remove(&p).map_err(|e| InstallError::Step {
            step: "managed".into(),
            detail: e.to_string(),
        })? != Change::Unchanged;
        if a.created_file && is_empty_config(&a.agent, &p) {
            fsops::remove_if_listed(&p).map_err(step("managed"))?;
            out.push(format!("removed {shown}"));
        } else if changed {
            out.push(format!("removed saiife's entry from {shown}"));
        }
    }

    // 4. The unit, daemon-reload, the binary.
    for kind in [FileKind::Unit, FileKind::Binary] {
        for f in rec.files.iter().rev().filter(|f| f.kind == kind) {
            if fsops::remove_if_listed(&at(&f.path)?).map_err(step("files"))? {
                out.push(format!("removed {}", f.path.display()));
            }
        }
        if kind == FileKind::Unit {
            systemctl_warn(host, &["daemon-reload"], &mut out);
        }
    }
    // Listed dirs outside /etc/saiife, if empty, innermost first.
    let etc = Path::new(ETC_DIR);
    for d in rec.dirs.iter().rev().filter(|d| !d.starts_with(etc)) {
        if fsops::remove_if_listed(&at(d)?).map_err(step("dirs"))? {
            out.push(format!("removed {}", d.display()));
        }
    }

    if !opts.purge {
        if fsops::remove_if_listed(&installed_path).map_err(step("installed.toml"))? {
            out.push(format!("removed {INSTALLED}"));
        }
        out.push(format!(
            "kept {ETC_DIR} (config, policy.d, vault key), {STATE_DIR}, {AUDIT_DIR} \
             and the {DAEMON_USER} user and groups (remove them with --purge)"
        ));
        return Ok(out);
    }

    // --purge: the config and vault key, state, audit, users and groups.
    for f in rec
        .files
        .iter()
        .rev()
        .filter(|f| matches!(f.kind, FileKind::Config | FileKind::VaultKey))
    {
        if fsops::remove_if_listed(&at(&f.path)?).map_err(step("files"))? {
            out.push(format!("removed {}", f.path.display()));
        }
    }
    // systemd made these for the daemon (StateDirectory, LogsDirectory).
    for abs in [STATE_DIR, AUDIT_DIR] {
        if fsops::remove_tree(&layout.at(abs)).map_err(step("purge"))? {
            out.push(format!("removed {abs}"));
        }
    }
    if fsops::remove_if_listed(&layout.at(LOG_DIR)).map_err(step("purge"))? {
        out.push(format!("removed {LOG_DIR}"));
    }
    for u in rec.users.iter().rev() {
        if host.user(u).is_some() {
            host.delete_user(u).map_err(step("users"))?;
            out.push(format!("deleted user {u}"));
        }
    }
    for g in rec.groups.iter().rev() {
        if host.group_id(g).is_some() {
            host.delete_group(g).map_err(step("users"))?;
            out.push(format!("deleted group {g}"));
        }
    }
    // Memberships install added go with the user or group it created.
    if fsops::remove_if_listed(&installed_path).map_err(step("installed.toml"))? {
        out.push(format!("removed {INSTALLED}"));
    }
    for d in rec.dirs.iter().rev().filter(|d| d.starts_with(etc)) {
        let p = at(d)?;
        if fsops::remove_if_listed(&p).map_err(step("dirs"))? {
            out.push(format!("removed {}", d.display()));
        } else if p.exists() {
            out.push(format!("kept {} (not empty)", d.display()));
        }
    }
    Ok(out)
}

fn systemctl_warn(host: &dyn Host, args: &[&str], out: &mut Vec<String>) {
    let line = args.join(" ");
    match host.systemctl(args) {
        Ok(o) if o.status == 0 => {}
        Ok(o) => out.push(format!(
            "warning: systemctl {line} exited {}: {}",
            o.status,
            o.stderr.trim()
        )),
        Err(e) => out.push(format!("warning: systemctl {line}: {e}")),
    }
}

/// True when a managed config holds nothing (after saiife's entry left).
fn is_empty_config(agent: &str, p: &Path) -> bool {
    let Ok(Some(text)) = saiife_agents::fsutil::read_managed(p) else {
        return false;
    };
    match agent {
        "codex" => text
            .parse::<toml_edit::DocumentMut>()
            .is_ok_and(|d| d.as_table().is_empty()),
        "gemini" => serde_json::from_str::<serde_json::Value>(&text)
            .is_ok_and(|v| v.as_object().is_some_and(|m| m.is_empty())),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::tests::{env, Env};
    use std::collections::BTreeSet;
    use std::fs;

    fn set(paths: &[&str]) -> BTreeSet<String> {
        paths.iter().map(|s| s.to_string()).collect()
    }

    /// Left by the test setup, not by install.
    const SETUP: &[&str] = &[
        ".fakehost.json",
        "etc",
        "etc/os-release",
        "run",
        "run/systemd",
        "run/systemd/system",
    ];

    fn un(e: &Env, purge: bool) -> Vec<String> {
        uninstall(&e.layout, &e.host, &UninstallOptions { purge }).unwrap()
    }

    #[test]
    fn uninstall_removes_exactly_what_install_listed() {
        let e = env(255);
        e.install();
        e.host.set(|s| s.calls.clear());
        let out = un(&e, false);
        let mut want = set(SETUP);
        want.extend(set(&[
            "etc/saiife",
            "etc/saiife/config.toml",
            "etc/saiife/policy.d",
            "etc/saiife/credstore",
            "etc/saiife/credstore/vault-key",
        ]));
        assert_eq!(e.tree(), want);
        let calls = e.host.state().calls;
        assert_eq!(calls[0], "systemctl disable --now saiifed.service");
        assert!(calls.contains(&"systemctl daemon-reload".to_string()));
        assert!(
            out.iter().any(|l| l.contains("/opt/saiife/bin/saiife")),
            "{out:?}"
        );
        // Users and groups are kept.
        let s = e.host.state();
        assert!(s.users.contains_key(DAEMON_USER));
        assert!(s.groups.contains_key(AUDIT_GROUP));
        // A second run has nothing to do.
        assert!(un(&e, false).is_empty());
    }

    #[test]
    fn changed_whole_file_is_removed_and_said() {
        let e = env(255);
        e.install();
        fs::write(e.at(CLAUDE_MANAGED), "{}").unwrap();
        let out = un(&e, false);
        assert!(!e.at(CLAUDE_MANAGED).exists());
        assert!(
            out.iter()
                .any(|l| l.contains("50-saiife.json") && l.contains("changed since install")),
            "{out:?}"
        );
    }

    #[test]
    fn purge_removes_all_and_created_users() {
        let e = env(249);
        e.install();
        // What the daemon would have made.
        fs::create_dir_all(e.at(KEYS_DIR)).unwrap();
        fs::write(e.at(AUDIT_KEY), "k").unwrap();
        fs::create_dir_all(e.at(AUDIT_DIR)).unwrap();
        fs::write(e.at(AUDIT_DIR).join("2026-10.jsonl"), "{}\n").unwrap();
        un(&e, true);
        // The parents the test made for the daemon's dirs stay (they exist
        // on every host); saiife's own dirs are gone.
        let mut want = set(SETUP);
        want.extend(set(&["var", "var/lib", "var/log"]));
        assert_eq!(e.tree(), want);
        let s = e.host.state();
        assert!(s.users.is_empty(), "{:?}", s.users);
        assert!(s.groups.is_empty(), "{:?}", s.groups);
    }

    #[test]
    fn purge_keeps_users_install_did_not_create_and_admin_drop_ins() {
        let e = env(255);
        e.host.set(|s| {
            s.groups.insert(DAEMON_GROUP.into(), 990);
        });
        e.install();
        fs::write(e.at(POLICY_D).join("shop.toml"), "").unwrap();
        un(&e, true);
        let s = e.host.state();
        assert!(s.groups.contains_key(DAEMON_GROUP));
        assert!(!s.groups.contains_key(AUDIT_GROUP));
        assert!(!s.users.contains_key(DAEMON_USER));
        assert!(e.at(POLICY_D).join("shop.toml").exists());
        assert!(!e.at(CONFIG).exists());
        assert!(!e.at(INSTALLED).exists());
    }

    #[test]
    fn uninstall_keeps_preexisting_codex_file() {
        let e = env(255);
        let original = "# admin\n[features]\nweb_search = true\n";
        fs::create_dir_all(e.at(CODEX_DIR)).unwrap();
        fs::write(e.at(CODEX_REQUIREMENTS), original).unwrap();
        e.install();
        assert_ne!(
            fs::read_to_string(e.at(CODEX_REQUIREMENTS)).unwrap(),
            original
        );
        un(&e, false);
        assert_eq!(
            fs::read_to_string(e.at(CODEX_REQUIREMENTS)).unwrap(),
            original
        );
    }

    #[test]
    fn created_shared_file_with_admin_additions_is_kept() {
        let e = env(255);
        e.install();
        // The admin adds a key to the file install created.
        let p = e.at(GEMINI_SETTINGS);
        let mut v: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
        v["general"] = serde_json::json!({"vimMode": true});
        fs::write(&p, serde_json::to_string_pretty(&v).unwrap()).unwrap();
        un(&e, false);
        let left: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(left, serde_json::json!({"general": {"vimMode": true}}));
    }

    #[test]
    fn uninstall_after_partial_install_is_clean() {
        let e = env(255);
        e.install();
        for abs in [BINARY, UNIT, CODEX_REQUIREMENTS, CLAUDE_MANAGED] {
            fs::remove_file(e.at(abs)).unwrap();
        }
        e.host.set(|s| {
            s.users.clear();
        });
        un(&e, true);
        assert_eq!(e.tree(), set(SETUP));
    }

    #[test]
    fn uninstall_without_installed_is_noop() {
        let e = env(255);
        assert!(un(&e, false).is_empty());
        assert!(un(&e, true).is_empty());
        assert!(e.host.state().calls.is_empty());
    }

    #[test]
    fn disable_failure_is_a_warning() {
        let e = env(255);
        e.install();
        e.host.set(|s| {
            s.run.insert(
                "systemctl disable --now saiifed.service".into(),
                crate::host::CmdOutput {
                    status: 5,
                    stdout: String::new(),
                    stderr: "Unit saiifed.service not loaded.".into(),
                },
            );
        });
        let out = un(&e, false);
        assert!(out.iter().any(|l| l.starts_with("warning:")), "{out:?}");
        assert!(!e.at(BINARY).exists());
    }

    #[test]
    fn unlisted_paths_are_never_touched() {
        let e = env(255);
        e.install();
        fs::write(e.at(BIN_DIR).join("other-tool"), "x").unwrap();
        un(&e, true);
        assert!(e.at(BIN_DIR).join("other-tool").exists());
        assert!(e.at(BIN_DIR).is_dir());
    }
}
