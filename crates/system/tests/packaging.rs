//! Layout guard for the Linux packages (plan 18, decision 1): the package owns
//! the staging binary, its symlink and the docs, and no path that `system
//! install` records in `installed.toml`.

use saiife_system::layout;
use std::path::PathBuf;

// matches layout::PACKAGE_BINARY (Task 1)
const PACKAGE_BINARY: &str = "/usr/libexec/saiife/saiife";

fn linux_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packaging/linux")
}

fn read(rel: &str) -> String {
    let p = linux_dir().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn dsts_from(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim_start().trim_start_matches("- ").trim_start();
            l.strip_prefix("dst:")
                .map(|v| v.trim().trim_matches(|c| c == '"' || c == '\'').to_string())
        })
        .collect()
}

fn dsts() -> Vec<String> {
    dsts_from(&read("nfpm.yaml"))
}

fn is_at_or_below(path: &str, root: &str) -> bool {
    path == root || path.strip_prefix(root).is_some_and(|r| r.starts_with('/'))
}

/// Allow-list: below /usr/, normalised, and not below any installed path.
fn check_dst(d: &str) -> Result<(), String> {
    if !d.starts_with("/usr/") || d.contains("//") || d.contains("..") {
        return Err(format!("{d}: not a normalised path below /usr/"));
    }
    let forbidden = [
        layout::OPT_DIR,
        layout::ETC_DIR,
        layout::UNIT,
        layout::STATE_DIR,
        layout::LOG_DIR,
        layout::RUN_DIR,
        layout::POLKIT_DIR,
        layout::CLAUDE_MANAGED_DIR,
        layout::CODEX_DIR,
        layout::GEMINI_DIR,
        "/usr/local",
        "/usr/share/polkit-1",
        "/etc",
        "/var",
        "/run",
        "/opt",
    ];
    for f in forbidden {
        if is_at_or_below(d, f) {
            return Err(format!("package owns {d}, below {f}"));
        }
    }
    Ok(())
}

#[test]
fn package_owns_no_installed_path() {
    let dsts = dsts();
    assert!(!dsts.is_empty(), "no dst entries parsed from nfpm.yaml");
    for d in &dsts {
        check_dst(d).unwrap();
    }
}

#[test]
fn guard_catches_bad_paths() {
    let yaml = "  - dst: \"/opt/saiife/bin/saiife\"\n  - dst: '/etc/foo'\n  - dst: /usr/share/polkit-1/rules.d/x\n  - dst: /usr/share/../etc/x\n  - dst: /usr//bin/x\n  - dst: /var/lib/x\n";
    let found = dsts_from(yaml);
    assert_eq!(found.len(), 6);
    assert_eq!(found[0], "/opt/saiife/bin/saiife");
    for d in &found {
        assert!(check_dst(d).is_err(), "{d} must be rejected");
    }
    assert!(check_dst("/usr/bin/saiife").is_ok());
}

#[test]
fn package_ships_the_staging_binary() {
    assert!(dsts().iter().any(|d| d == PACKAGE_BINARY));
}

#[test]
fn postinst_runs_fleet_install() {
    let s = read("scripts/postinst");
    assert!(s.contains(&format!("{PACKAGE_BINARY} system install --fleet")));
    assert!(s.contains(r#"[ "$rc" -eq 1 ]"#), "exit 1 must map to 0");
}

#[test]
fn prerm_uninstalls_on_remove_only() {
    let s = read("scripts/prerm");
    let call = format!("{PACKAGE_BINARY} system uninstall");
    assert_eq!(s.matches(&call).count(), 1);
    let branch = s.split("remove|0)").nth(1).expect("remove|0) branch");
    let branch = branch.split(";;").next().unwrap();
    assert!(branch.contains(&call), "uninstall must sit in remove|0)");
    assert!(s.contains(
        "saiife: removing the package uninstalls locked mode: agents on this machine will no longer be locked"
    ));
    assert!(s.contains("logger -t saiife -p auth.warning"));
}

#[test]
fn scripts_are_posix_sh() {
    for name in ["scripts/postinst", "scripts/prerm"] {
        let s = read(name);
        assert_eq!(s.lines().next(), Some("#!/bin/sh"), "{name}");
        for bad in ["[[", "local ", "$'"] {
            assert!(!s.contains(bad), "{name} uses {bad}");
        }
    }
}
