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

fn dsts() -> Vec<String> {
    read("nfpm.yaml")
        .lines()
        .filter_map(|l| {
            let l = l.trim_start().trim_start_matches("- ").trim_start();
            l.strip_prefix("dst:").map(|v| v.trim().to_string())
        })
        .collect()
}

fn is_at_or_below(path: &str, root: &str) -> bool {
    path == root || path.strip_prefix(root).is_some_and(|r| r.starts_with('/'))
}

#[test]
fn package_owns_no_installed_path() {
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
    ];
    let dsts = dsts();
    assert!(!dsts.is_empty(), "no dst entries parsed from nfpm.yaml");
    for d in &dsts {
        for f in forbidden {
            assert!(!is_at_or_below(d, f), "package owns {d}, below {f}");
        }
    }
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
    assert!(s.contains("exit 0"));
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
