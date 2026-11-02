//! Layout guard for the packages (plan 18, decision 1): a package owns the
//! staging binary, its symlink and the docs, and no path that `system install`
//! records in `installed.toml`. The macOS checks read text and run scripts
//! that stop before they change anything, so they run on every platform.

use saiife_system::layout::{self, Layout, Platform};
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

// ---------------------------------------------------------------- macOS pkg

const PKG_BINARY: &str = "/usr/local/libexec/saiife/saiife";
const PKG_LINK: &str = "/usr/local/bin/saiife";

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn repo_read(rel: &str) -> String {
    let p = repo().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// The paths named by `build-pkg.sh`'s `PAYLOAD_*=` lines, absolute.
fn pkg_payload_from(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| {
            let (name, value) = l.split_once('=')?;
            name.starts_with("PAYLOAD_").then(|| format!("/{value}"))
        })
        .collect()
}

/// Allow-list: below /usr/local, normalised, and not below any path of the
/// §5.3 tree.
fn check_pkg_path(p: &str) -> Result<(), String> {
    if !p.starts_with("/usr/local/") || p.contains("//") || p.contains("..") {
        return Err(format!("{p}: not a normalised path below /usr/local/"));
    }
    let mac = Layout::under_for("/x", Platform::Macos);
    let forbidden = [
        layout::OPT_DIR,
        layout::ETC_DIR,
        layout::UNIT,
        layout::STATE_DIR,
        layout::LOG_DIR,
        layout::RUN_DIR,
        layout::CLAUDE_MANAGED_DIR,
        layout::CODEX_DIR,
        layout::GEMINI_DIR,
    ]
    .map(|c| mac.logical(c));
    for f in forbidden
        .into_iter()
        .chain(["/etc", "/var", "/opt", "/Library", "/private"])
    {
        if is_at_or_below(p, f) {
            return Err(format!("pkg owns {p}, below {f}"));
        }
    }
    Ok(())
}

#[test]
fn pkg_payload_owns_no_installed_path() {
    let payload = pkg_payload_from(&repo_read("packaging/macos/build-pkg.sh"));
    assert_eq!(payload, [PKG_BINARY, PKG_LINK]);
    for p in &payload {
        check_pkg_path(p).unwrap();
    }
    let mac = Layout::under_for("/x", Platform::Macos);
    assert_eq!(mac.logical(layout::PACKAGE_BINARY), PKG_BINARY);
    for bad in [
        "/opt/saiife/bin/saiife",
        "/etc/saiife/x",
        "/var/db/saiife/x",
        "/Library/LaunchDaemons/com.saiife.saiifed.plist",
        "/usr/bin/saiife",
        "/usr/local/../etc/x",
        "/usr/local//x",
    ] {
        assert!(check_pkg_path(bad).is_err(), "{bad} must be rejected");
    }
}

#[test]
fn pkg_postinstall_runs_fleet_install() {
    let s = repo_read("packaging/macos/scripts/postinstall");
    assert!(s.contains(&format!("PKG_BIN={PKG_BINARY}\n")));
    assert_eq!(s.matches(r#""$PKG_BIN" system install --fleet"#).count(), 1);
    assert!(s.contains(r#"[ "$3" != "/" ]"#));
    assert!(s.contains(r#"exit "$rc""#));
}

#[test]
fn pkg_is_for_one_architecture() {
    let b = repo_read("packaging/macos/build-pkg.sh");
    assert!(b.contains(r#"[ "$(lipo -archs "$bin")" = "$arch" ]"#));
    assert!(b.contains("IDENTIFIER=com.saiife.pkg"));
    assert!(b.contains("--install-location /"));
    assert!(b.contains("::notice::pkg unsigned"));
    // Plan 13 uses an Apple ID with an app-specific password, not an API key.
    for flag in ["--apple-id", "--team-id", "--password"] {
        assert!(b.contains(flag), "{flag}");
    }
    let d = repo_read("packaging/macos/distribution.xml");
    for want in [
        r#"hostArchitectures="@ARCH@""#,
        r#"require-scripts="true""#,
        r#"<pkg-ref id="com.saiife.pkg" version="@VERSION@""#,
        ">saiife-component.pkg</pkg-ref>",
    ] {
        assert!(d.contains(want), "{want}");
    }
}

/// `sh` on `rel` from a copy under `d`, with the paths in `swap` replaced. The
/// replacements call the stubs through `sh`: a test never execs a file it just
/// wrote (ETXTBSY when another test thread forks at that moment).
fn run_copy(
    d: &std::path::Path,
    rel: &str,
    swap: &[(&str, String)],
    args: &[&str],
) -> (Option<i32>, String, String) {
    let mut s = repo_read(rel);
    for (from, to) in swap {
        assert!(s.contains(from), "{rel} lacks {from}");
        s = s.replace(from, to);
    }
    let copy = d.join("script-copy");
    std::fs::write(&copy, s).unwrap();
    let out = std::process::Command::new("sh")
        .arg(&copy)
        .args(args)
        .current_dir(d)
        .output()
        .expect("sh");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

const POSTINSTALL: &str = "packaging/macos/scripts/postinstall";

/// The test's uid: a staging tree here cannot be root's.
fn my_uid() -> String {
    let out = std::process::Command::new("id").arg("-u").output().unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A safe staging tree below `d`, as `/usr/local`: returns that dir and the
/// binary, a stub that exits `code`.
fn staging_tree(d: &std::path::Path, code: i32) -> (PathBuf, PathBuf) {
    let local = d.join("local");
    let bin = local.join("libexec/saiife/saiife");
    std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
    std::fs::write(
        &bin,
        format!("echo \"called: $*\"\necho 'saiife: the last line'\nexit {code}\n"),
    )
    .unwrap();
    // Whatever the umask of the run.
    for p in [
        local.clone(),
        local.join("libexec"),
        local.join("libexec/saiife"),
        bin.clone(),
    ] {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    (local, bin)
}

/// The postinstall in the tree `local`, with a `logger` stub; the `logger`
/// arguments, if any, are returned last. The check's expected owner is the
/// test's uid.
fn postinstall_in(
    d: &std::path::Path,
    local: &std::path::Path,
    volume: &str,
) -> (Option<i32>, String, String, String) {
    let log = d.join("logged");
    let logger = d.join("fake-logger");
    std::fs::write(&logger, format!("echo \"$*\" >>'{}'\n", log.display())).unwrap();
    let (rc, out, err) = run_copy(
        d,
        POSTINSTALL,
        &[
            ("/usr/local", local.display().to_string()),
            ("STAGING_UID=0", format!("STAGING_UID={}", my_uid())),
            // -e is macOS's; GNU ls refuses it.
            ("ls -ldne", "ls -ldn".to_string()),
            (
                r#""$PKG_BIN" system install"#,
                r#"sh "$PKG_BIN" system install"#.to_string(),
            ),
            ("logger -t", format!("sh '{}' -t", logger.display())),
        ],
        &["/some/saiife.pkg", "/", volume],
    );
    let logged = std::fs::read_to_string(&log).unwrap_or_default();
    (rc, out, err, logged)
}

fn postinstall(code: i32, volume: &str) -> (Option<i32>, String, String, String) {
    let d = tempfile::tempdir().unwrap();
    let (local, _) = staging_tree(d.path(), code);
    postinstall_in(d.path(), &local, volume)
}

#[test]
fn pkg_postinstall_refuses_an_unsafe_staging_path() {
    use std::os::unix::fs::PermissionsExt;
    let chmod = |p: &std::path::Path, m: u32| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap()
    };
    let refused = |d: &std::path::Path, local: &std::path::Path, want: String| {
        let (rc, out, err, logged) = postinstall_in(d, local, "/");
        assert_eq!(rc, Some(2), "{out}{err}");
        assert!(!out.contains("called:"), "must not run it: {out}");
        assert!(err.contains(&want), "want {want}: {err}");
        assert!(logged.contains("-p auth.err"), "{logged}");
    };
    // Each step of the walk: group- or world-writable.
    let d = tempfile::tempdir().unwrap();
    let (local, bin) = staging_tree(d.path(), 0);
    for (p, mode, back) in [
        (local.clone(), 0o775, 0o755),
        (local.join("libexec"), 0o757, 0o755),
        (local.join("libexec/saiife"), 0o775, 0o755),
        (bin.clone(), 0o775, 0o755),
    ] {
        chmod(&p, mode);
        refused(
            d.path(),
            &local,
            format!("{} is writable by group or others", p.display()),
        );
        chmod(&p, back);
    }
    let (rc, out, ..) = postinstall_in(d.path(), &local, "/");
    assert_eq!(rc, Some(0));
    assert!(out.contains("called: system install --fleet"), "{out}");

    // A symlink for the binary or a dir, even to a safe target.
    let moved = d.path().join("moved");
    std::fs::rename(&bin, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &bin).unwrap();
    refused(
        d.path(),
        &local,
        format!("{} is a symbolic link", bin.display()),
    );
    std::fs::remove_file(&bin).unwrap();
    // Missing, and a directory where the binary should be.
    refused(d.path(), &local, format!("{} is missing", bin.display()));
    std::fs::create_dir(&bin).unwrap();
    refused(
        d.path(),
        &local,
        format!("{} is not a regular file", bin.display()),
    );

    // Someone else's: the real script wants uid 0.
    let d = tempfile::tempdir().unwrap();
    let (local, _) = staging_tree(d.path(), 0);
    let (rc, out, err) = run_copy(
        d.path(),
        POSTINSTALL,
        &[
            ("/usr/local", local.display().to_string()),
            ("STAGING_UID=0", "STAGING_UID=4242".to_string()),
            ("ls -ldne", "ls -ldn".to_string()),
            ("logger -t", ": -t".to_string()),
        ],
        &["/some/saiife.pkg", "/", "/"],
    );
    assert_eq!(rc, Some(2), "{out}{err}");
    assert!(
        err.contains(&format!("{} is not owned by root", local.display())),
        "{err}"
    );
}

#[test]
fn staging_check_is_the_same_in_all_three_scripts() {
    let check = |rel: &str| -> String {
        let s = repo_read(rel);
        let (_, rest) = s.split_once("# --- staging check:").expect(rel);
        let (body, _) = rest.split_once("# --- end staging check ---").expect(rel);
        body.to_string()
    };
    let p = check(POSTINSTALL);
    assert!(p.contains("STAGING_UID=0\n"));
    assert_eq!(p, check("deploy/jamf/fleet-files.sh"));
    assert_eq!(p, check("deploy/intune/macos/fleet-files.sh"));
}

#[test]
fn pkg_postinstall_passes_on_0_and_1_and_fails_loudly_on_2() {
    let (rc, out, err, logged) = postinstall(0, "/");
    assert_eq!(rc, Some(0), "{out}{err}");
    assert!(out.contains("called: system install --fleet"), "{out}");
    assert_eq!(logged, "");

    let (rc, out, err, logged) = postinstall(1, "/");
    assert_eq!(rc, Some(0), "{out}{err}");
    assert!(out.contains("the last line"), "{out}");
    assert!(logged.contains("-p auth.warning"), "{logged}");

    let (rc, out, err, logged) = postinstall(2, "/");
    assert_eq!(rc, Some(2), "a refusal must fail the pkg: {out}{err}");
    assert!(out.contains("the last line"), "the refusal is shown: {out}");
    let want = "saiife: install did not complete and may be partial; do not assume locked \
                mode is active; run /opt/saiife/bin/saiife doctor: \
                system install --fleet exited 2: saiife: the last line";
    assert!(err.contains(want), "{err}");
    assert!(logged.contains("-p auth.err"), "{logged}");
    assert!(logged.contains(want), "{logged}");
}

/// Only an install that says it changed nothing gets the claim.
#[test]
fn pkg_postinstall_claims_unchanged_only_when_install_says_so() {
    let d = tempfile::tempdir().unwrap();
    let (local, bin) = staging_tree(d.path(), 2);
    std::fs::write(
        &bin,
        "echo 'saiife: locked mode on macOS needs SIP' >&2\n\
         echo 'saiife: nothing was changed' >&2\nexit 2\n",
    )
    .unwrap();
    let (rc, out, err, logged) = postinstall_in(d.path(), &local, "/");
    assert_eq!(rc, Some(2), "{out}{err}");
    let want = "saiife: install did not complete; any earlier install is unchanged: \
                system install --fleet exited 2: saiife: locked mode on macOS needs SIP";
    assert!(err.contains(want), "{err}");
    assert!(logged.contains(want), "{logged}");
    assert!(!err.contains("may be partial"), "{err}");
}

/// `ls` here cannot show a macOS ACL, so a stub does: clean mode bits, and
/// then what macOS prints.
#[test]
fn pkg_postinstall_refuses_an_acl() {
    for listing in [
        // A "+" after the mode.
        "drwxr-xr-x+ 3 UID 0 96 Nov  2 07:00 x",
        // "@" instead of "+": an extended attribute hides it there, and only
        // the entry line shows the ACL.
        "drwxr-xr-x@ 3 UID 0 96 Nov  2 07:00 x\n 0: group:everyone allow write",
    ] {
        let d = tempfile::tempdir().unwrap();
        let (local, _) = staging_tree(d.path(), 0);
        let ls = d.path().join("fake-ls");
        let listing = listing.replace("UID", &my_uid());
        std::fs::write(&ls, format!("printf '%s\\n' '{listing}'\n")).unwrap();
        let (rc, out, err) = run_copy(
            d.path(),
            POSTINSTALL,
            &[
                ("/usr/local", local.display().to_string()),
                ("STAGING_UID=0", format!("STAGING_UID={}", my_uid())),
                ("ls -ldne", format!("sh '{}'", ls.display())),
                ("logger -t", ": -t".to_string()),
            ],
            &["/some/saiife.pkg", "/", "/"],
        );
        assert_eq!(rc, Some(2), "{listing}: {out}{err}");
        assert!(!out.contains("called:"), "must not run it: {out}");
        assert!(
            err.contains(&format!("{} has an ACL", local.display())),
            "{listing}: {err}"
        );
        assert!(err.contains("chmod -N"), "{err}");
    }
    // An extended attribute alone is not an ACL.
    let d = tempfile::tempdir().unwrap();
    let (local, _) = staging_tree(d.path(), 0);
    let ls = d.path().join("fake-ls");
    std::fs::write(
        &ls,
        format!(
            "printf '%s\\n' 'drwxr-xr-x@ 3 {} 0 96 Nov  2 07:00 x'\n",
            my_uid()
        ),
    )
    .unwrap();
    let (rc, out, err) = run_copy(
        d.path(),
        POSTINSTALL,
        &[
            ("/usr/local", local.display().to_string()),
            ("STAGING_UID=0", format!("STAGING_UID={}", my_uid())),
            ("ls -ldne", format!("sh '{}'", ls.display())),
            (
                r#""$PKG_BIN" system install"#,
                r#"sh "$PKG_BIN" system install"#.to_string(),
            ),
            ("logger -t", ": -t".to_string()),
        ],
        &["/some/saiife.pkg", "/", "/"],
    );
    assert_eq!(rc, Some(0), "{out}{err}");
    assert!(out.contains("called: system install --fleet"), "{out}");
}

#[test]
fn pkg_postinstall_skips_another_volume() {
    let (rc, out, err, logged) = postinstall(2, "/Volumes/Other");
    assert_eq!(rc, Some(0), "{out}{err}");
    assert_eq!(
        out,
        "saiife: not the boot volume; run system install --fleet after boot\n"
    );
    assert_eq!(logged, "");
}

/// The attribute script against a `doctor` that exits `code` (`None`: not
/// installed). BIN becomes /bin/sh, which then runs the file `doctor` in the
/// script's cwd, so no file written here is ever exec'd.
fn attribute(rel: &str, code: Option<i32>) -> (Option<i32>, String) {
    let d = tempfile::tempdir().unwrap();
    let bin = match code {
        Some(c) => {
            std::fs::write(d.path().join("doctor"), format!("exit {c}\n")).unwrap();
            "/bin/sh".to_string()
        }
        None => d.path().join("not-there").display().to_string(),
    };
    let (rc, out, _) = run_copy(d.path(), rel, &[("/opt/saiife/bin/saiife", bin)], &[]);
    (rc, out)
}

#[test]
fn jamf_extension_attribute_follows_doctor() {
    let rel = "deploy/jamf/extension-attribute.sh";
    for (code, want) in [
        (Some(0), "<result>pass</result>\n"),
        (Some(1), "<result>warn</result>\n"),
        (Some(2), "<result>fail</result>\n"),
        (None, "<result>not installed</result>\n"),
    ] {
        assert_eq!(
            attribute(rel, code),
            (Some(0), want.to_string()),
            "{code:?}"
        );
    }
}

#[test]
fn intune_custom_attribute_prints_doctors_exit() {
    let rel = "deploy/intune/macos/custom-attribute.sh";
    for (code, want) in [
        (Some(0), "0\n"),
        (Some(1), "1\n"),
        (Some(2), "2\n"),
        (None, "not installed\n"),
    ] {
        assert_eq!(
            attribute(rel, code),
            (Some(0), want.to_string()),
            "{code:?}"
        );
    }
}

fn is_root() -> bool {
    let out = std::process::Command::new("id").arg("-u").output().unwrap();
    String::from_utf8_lossy(&out.stdout).trim() == "0"
}

/// The Jamf fleet script: its input checks, then its root check. Never run
/// as root here: past that check it writes /etc.
fn jamf_fleet_files(config_b64: &str, agents: &str) -> (Option<i32>, String) {
    let out = std::process::Command::new("sh")
        .arg(repo().join("deploy/jamf/fleet-files.sh"))
        .args(["/", "host", "user", config_b64, agents])
        .output()
        .expect("sh");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn fleet_files_check_their_input_then_refuse_non_root() {
    if is_root() {
        eprintln!("skipped: running as root");
        return;
    }
    // "version = 2\n" in base64.
    let good = "dmVyc2lvbiA9IDIK";
    for (b64, agents, want) in [
        ("", "claude", "no config"),
        ("Cg==", "claude", "the config is empty"),
        (good, "claude,evil\"]", "unknown agent: evil"),
        (good, "claude, codex", "unknown agent:  codex"),
        (good, "claude,codex,gemini", "must run as root"),
        (good, "", "must run as root"),
    ] {
        let (rc, err) = jamf_fleet_files(b64, agents);
        assert_eq!(rc, Some(2), "{b64} {agents}: {err}");
        assert!(err.contains(want), "{b64} {agents}: {err}");
    }
}

#[test]
fn fleet_scripts_share_one_body() {
    let body = |rel: &str| -> String {
        let s = repo_read(rel);
        let (_, rest) = s.split_once("--- The rest is the same as").expect(rel);
        rest.split_once('\n').expect(rel).1.to_string()
    };
    let jamf = body("deploy/jamf/fleet-files.sh");
    assert_eq!(jamf, body("deploy/intune/macos/fleet-files.sh"));
    assert!(jamf.contains("chown root:wheel"));
    assert!(jamf.contains(&format!("PKG_BIN={PKG_BINARY}\n")));
    assert!(jamf.contains(r#""$PKG_BIN" system install --fleet"#));
    // Checked before anything is written, and before it is run.
    let check = jamf.find("why=$(staging_problem)").unwrap();
    assert!(check < jamf.find(r#"put "$FLEET/config.toml""#).unwrap());
    assert!(check < jamf.find(r#""$PKG_BIN" system install"#).unwrap());
    let top = repo_read("deploy/jamf/fleet-files.sh");
    assert!(top.contains("CONFIG_B64=$4\nAGENTS=$5\n"));
    assert!(repo_read("deploy/intune/macos/fleet-files.sh").contains("CONFIG_B64=\"\"\n"));
}

#[test]
fn jamf_uninstall_warns_then_removes() {
    let s = repo_read("deploy/jamf/uninstall.sh");
    assert!(s.contains(
        "saiife: removing the package uninstalls locked mode: agents on this machine will no longer be locked"
    ));
    assert!(s.contains("logger -t saiife -p auth.warning"));
    let order = [
        r#"echo "$msg" >&2"#,
        r#""$BIN" system uninstall"#,
        r#"rm -rf "$STAGING_DIR""#,
        "pkgutil --forget com.saiife.pkg",
    ];
    let at: Vec<usize> = order
        .iter()
        .map(|w| s.find(w).unwrap_or_else(|| panic!("{w}")))
        .collect();
    assert!(at.windows(2).all(|w| w[0] < w[1]), "{at:?}");
    if !is_root() {
        let out = std::process::Command::new("sh")
            .arg(repo().join("deploy/jamf/uninstall.sh"))
            .output()
            .expect("sh");
        assert_eq!(out.status.code(), Some(2));
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(err, "saiife: uninstall: must run as root\n");
    }
}

/// These two touch the machine past their gate, so they are only ever run with
/// the gate's variables removed.
#[test]
fn macos_ci_scripts_refuse_outside_ci() {
    for rel in ["packaging/macos/build-pkg.sh", "scripts/macos-pkg/run.sh"] {
        let out = std::process::Command::new("bash")
            .arg(repo().join(rel))
            .env_remove("GITHUB_ACTIONS")
            .env_remove("SAIIFE_PACKAGE_CI")
            .output()
            .expect("bash");
        assert_eq!(out.status.code(), Some(2), "{rel}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.starts_with("refusing: "), "{rel}: {err}");
    }
}

#[test]
fn macos_scripts_are_posix_sh() {
    for rel in [
        POSTINSTALL,
        "deploy/jamf/fleet-files.sh",
        "deploy/jamf/extension-attribute.sh",
        "deploy/jamf/uninstall.sh",
        "deploy/intune/macos/fleet-files.sh",
        "deploy/intune/macos/custom-attribute.sh",
    ] {
        let s = repo_read(rel);
        assert_eq!(s.lines().next(), Some("#!/bin/sh"), "{rel}");
        for bad in ["[[", "$'"] {
            assert!(!s.contains(bad), "{rel} uses {bad}");
        }
        // Not the /usr/local of a path.
        assert!(
            !s.lines().any(|l| l.trim_start().starts_with("local ")),
            "{rel} uses local"
        );
    }
}
