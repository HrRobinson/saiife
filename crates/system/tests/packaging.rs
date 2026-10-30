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

#[test]
fn intune_rules_match_discovery() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/intune/linux");
    let script = std::fs::read_to_string(dir.join("discovery.sh")).expect("discovery.sh");
    let rules: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("rules.json")).expect("rules.json"))
            .expect("rules.json is JSON");
    let rules = rules["Rules"].as_array().expect("Rules array");
    let mut seen = Vec::new();
    for r in rules {
        let name = r["SettingName"].as_str().expect("SettingName");
        assert!(script.contains(name), "{name} missing from discovery.sh");
        seen.push((
            name.to_string(),
            r["Operator"].as_str().unwrap().to_string(),
            r["Operand"].clone(),
        ));
    }
    seen.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        seen,
        vec![
            (
                "saiife_doctor_exit".into(),
                "LessEquals".into(),
                serde_json::json!(1)
            ),
            (
                "saiife_installed".into(),
                "IsEquals".into(),
                serde_json::json!(true)
            ),
        ]
    );
}

/// rpm removes only the dirs a package lists: the staging dir must be one.
#[test]
fn package_owns_its_staging_dir() {
    let y = read("nfpm.yaml");
    assert!(
        y.contains(
            "  - dst: /usr/libexec/saiife\n    type: dir\n    file_info:\n      mode: 0755\n"
        ),
        "nfpm.yaml lacks the /usr/libexec/saiife dir entry"
    );
}

/// nfpm takes the rpm key only from the YAML; an empty value is unsigned.
#[test]
fn rpm_key_file_is_in_the_yaml() {
    let y = read("nfpm.yaml");
    assert!(
        y.contains("\nrpm:\n  signature:\n    key_file: ${NFPM_RPM_KEY_FILE}\n"),
        "nfpm.yaml lacks rpm.signature.key_file"
    );
    let b = read("build.sh");
    assert!(b.contains("export NFPM_RPM_KEY_FILE=$SAIIFE_PKG_GPG_KEY_FILE"));
}

fn build_sh(version: &str) -> (Option<i32>, String) {
    let out = std::process::Command::new("bash")
        .arg(linux_dir().join("build.sh"))
        .args(["/nonexistent/p18-saiife", version, "amd64"])
        .arg(linux_dir().join("../../target/p18-never-written"))
        .output()
        .expect("bash");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A Cargo prerelease becomes a dpkg/rpm one ('-' -> '~'); the version
/// check runs before anything is built.
#[test]
fn build_maps_a_cargo_prerelease() {
    for (given, want) in [
        ("0.3.0", "0.3.0"),
        ("0.3.0-rc.1", "0.3.0~rc.1"),
        ("0.3.0~rc.1", "0.3.0~rc.1"),
        ("0.3.0-rc.1+ci1", "0.3.0~rc.1+ci1"),
    ] {
        let (code, err) = build_sh(given);
        assert_eq!(code, Some(2), "{given}: {err}");
        assert!(
            err.contains(&format!("build.sh: package version {want}\n")),
            "{given}: {err}"
        );
        assert!(err.contains("no such binary"), "{given}: {err}");
    }
    for bad in ["1.2", "v1.2.3", "1.2.3-", "1.2.3 x"] {
        let (code, err) = build_sh(bad);
        assert_eq!(code, Some(2), "{bad}: {err}");
        assert!(err.contains("version must look like"), "{bad}: {err}");
    }
}
