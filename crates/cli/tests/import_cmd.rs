//! `saiife secret import` against a real daemon on temp dirs (plan 10,
//! Task 17). The daemon runs as the test user and admin ops authorize
//! through `[admin] groups = [<primary group>]`. The agent user's home is a
//! fake one in a temp dir (never the real home, never /tmp).
#![cfg(target_os = "linux")]

mod common;

use common::daemon::{own_group, own_user, Opts, TestDaemon};
use serde_json::Value;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

fn admin_opts() -> Opts {
    Opts {
        extra: format!("[admin]\ngroups = [{:?}]\n", own_group()),
        ..Opts::default()
    }
}

fn admin() -> TestDaemon {
    TestDaemon::start(admin_opts())
}

/// A fake home (and project) dir below the test scratch dir.
fn scratch() -> TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

fn put(base: &Path, rel: &str, text: &str, mode: u32) -> PathBuf {
    let p = base.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(&p, text).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
    p
}

fn saiife(d: &TestDaemon, args: &[&str]) -> Output {
    saiife_env(d, args, &[])
}

fn saiife_env(d: &TestDaemon, args: &[&str], envs: &[(&str, &str)]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_saiife"))
        .envs(envs.iter().copied())
        .arg("secret")
        .arg("--system-config")
        .arg(d.config())
        .args(args)
        .env("HOME", d.path().join("home"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAIIFE_DATA_DIR", d.path().join("data"))
        .env("SAIIFE_AUDIT_DIR", d.audit_dir())
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn import(d: &TestDaemon, home: &Path, extra: &[&str]) -> Output {
    import_env(d, home, extra, &[])
}

fn import_env(d: &TestDaemon, home: &Path, extra: &[&str], envs: &[(&str, &str)]) -> Output {
    let user = own_user();
    let home = home.to_str().unwrap();
    let mut args = vec!["import", "--user", user.as_str(), "--home", home];
    args.extend_from_slice(extra);
    saiife_env(d, &args, envs)
}

fn svc(p: &Path, s: &str) -> String {
    format!("{}={s}", p.display())
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn all(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn names(d: &TestDaemon) -> Vec<(String, Value)> {
    let o = saiife(d, &["list", "--json"]);
    assert_eq!(o.status.code(), Some(0), "{}", all(&o));
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    v["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["name"].as_str().unwrap().to_string(),
                s["allowed_services"].clone(),
            )
        })
        .collect()
}

fn backup_dir(d: &TestDaemon) -> PathBuf {
    d.state_dir().join("state/import-backup")
}

fn backups(d: &TestDaemon) -> Vec<PathBuf> {
    match fs::read_dir(backup_dir(d)) {
        Ok(rd) => rd.map(|e| e.unwrap().path()).collect(),
        Err(_) => Vec::new(),
    }
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Everything the daemon wrote that a person or a log reader may see.
fn audit_text(d: &TestDaemon) -> String {
    let mut s = String::new();
    for r in d.records() {
        s.push_str(&r.to_string());
    }
    s.push_str(&d.stderr_text());
    s
}

#[test]
fn env_line_imported_and_removed() {
    let d = admin();
    let home = scratch();
    let proj = home.path().join("proj");
    let original = "PORT=8080\nGITHUB_TOKEN=ghp_envvalue_0001\nDEBUG=1\n";
    let env = put(&proj, ".env", original, 0o640);
    let ino = fs::metadata(&env).unwrap().ino();

    let o = import(
        &d,
        home.path(),
        &[
            "--project",
            proj.to_str().unwrap(),
            "--yes-to",
            env.to_str().unwrap(),
        ],
    );
    assert_eq!(o.status.code(), Some(0), "{}", all(&o));
    let user = own_user();
    let name = format!("{user}-github-token");
    let text = out(&o);
    assert!(
        text.contains(&format!("stored {name} from {}", env.display())),
        "{text}"
    );
    assert!(
        text.contains(&format!("next: saiife connect github --secret {name}")),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "rotate this credential: it was readable by {user}"
        )),
        "{text}"
    );

    // The line is gone, the rest stays, owner and mode are kept; the
    // file is a new inode (temp file and rename).
    assert_eq!(fs::read_to_string(&env).unwrap(), "PORT=8080\nDEBUG=1\n");
    let m = fs::metadata(&env).unwrap();
    assert_eq!(m.mode() & 0o7777, 0o640);
    assert_eq!(m.uid(), common::daemon::own_uid());
    assert_ne!(m.ino(), ino);
    // No temp file is left next to it.
    let left: Vec<_> = fs::read_dir(&proj)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(left, vec![std::ffi::OsString::from(".env")]);

    let n = names(&d);
    assert_eq!(n.len(), 1, "{n:?}");
    assert_eq!(n[0].0, name);
    assert_eq!(n[0].1, serde_json::json!(["github"]));

    // The backup holds the original bytes, 0600 in a 0700 dir.
    let b = backups(&d);
    assert_eq!(b.len(), 1, "{b:?}");
    assert_eq!(fs::read_to_string(&b[0]).unwrap(), original);
    assert_eq!(fs::metadata(&b[0]).unwrap().mode() & 0o777, 0o600);
    assert_eq!(fs::metadata(backup_dir(&d)).unwrap().mode() & 0o777, 0o700);
    let fname = b[0].file_name().unwrap().to_str().unwrap().to_string();
    assert!(fname.ends_with("_proj_.env"), "{fname}");
    assert!(fname
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-')));

    // The add is recorded with its source, never its value.
    let recs = d.of_kind("secret");
    let add = recs
        .iter()
        .find(|r| r["event"] == "secret_add")
        .expect("a secret_add record");
    assert_eq!(add["imported_from"], env.to_str().unwrap());
}

#[test]
fn git_credentials_imported() {
    let d = admin();
    let home = scratch();
    let creds = put(
        home.path(),
        ".git-credentials",
        "https://alice:ghp_gitvalue_0002@github.com\n",
        0o600,
    );
    let o = import(&d, home.path(), &["--yes-to", creds.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0), "{}", all(&o));
    let name = format!("{}-git-github.com", own_user());
    let n = names(&d);
    assert_eq!(n.len(), 1, "{n:?}");
    assert_eq!(n[0].0, name);
    assert_eq!(n[0].1, serde_json::json!(["github"]));
    assert_eq!(fs::read_to_string(&creds).unwrap(), "");
    assert_eq!(fs::metadata(&creds).unwrap().mode() & 0o7777, 0o600);
    assert!(out(&o).contains(&format!("next: saiife connect github --secret {name}")));
}

#[test]
fn failed_add_leaves_source_untouched() {
    let mut d = TestDaemon::prepare(&admin_opts());
    let vdir = d.state_dir().join("vault");
    fs::create_dir_all(&vdir).unwrap();
    fs::write(
        vdir.join("vault.bin"),
        b"not a vault, not even close...........",
    )
    .unwrap();
    d.spawn_and_wait();
    let home = scratch();
    let original = "GITHUB_TOKEN=ghp_failvalue_0003\n";
    let env = put(home.path(), "p/.env", original, 0o644);
    let ino = fs::metadata(&env).unwrap().ino();
    let o = import(
        &d,
        home.path(),
        &[
            "--project",
            home.path().join("p").to_str().unwrap(),
            "--yes-to",
            env.to_str().unwrap(),
        ],
    );
    assert_eq!(o.status.code(), Some(2), "{}", all(&o));
    assert!(
        out(&o).contains("not stored: vault cannot be read"),
        "{}",
        all(&o)
    );
    assert_eq!(fs::read(&env).unwrap(), original.as_bytes());
    assert_eq!(fs::metadata(&env).unwrap().ino(), ino);
    assert!(backups(&d).is_empty());
    assert!(!all(&o).contains("ghp_failvalue_0003"));
}

#[test]
fn aws_listed_not_touched() {
    let d = admin();
    let home = scratch();
    let text =
        "[default]\naws_access_key_id = AKIAEXAMPLE0004\naws_secret_access_key = awsvalue0004\n";
    let aws = put(home.path(), ".aws/credentials", text, 0o600);
    let kube = put(home.path(), ".kube/config", "token: kubevalue0004\n", 0o600);
    let o = import(
        &d,
        home.path(),
        &[
            "--yes-to",
            aws.to_str().unwrap(),
            "--yes-to",
            kube.to_str().unwrap(),
        ],
    );
    assert_eq!(o.status.code(), Some(0), "{}", all(&o));
    let t = out(&o);
    for p in [&aws, &kube] {
        assert!(
            t.contains(&format!(
                "{}: holds credentials: cloud credentials come with plan 15; remove or rotate by hand",
                p.display()
            )),
            "{t}"
        );
    }
    assert_eq!(fs::read_to_string(&aws).unwrap(), text);
    assert_eq!(fs::read_to_string(&kube).unwrap(), "token: kubevalue0004\n");
    assert!(names(&d).is_empty());
    assert!(backups(&d).is_empty());
    assert!(!all(&o).contains("awsvalue0004"));
}

#[test]
fn no_terminal_skips_and_lists() {
    let d = admin();
    let home = scratch();
    let vt = put(home.path(), ".vault-token", "hvs.skipvalue0005\n", 0o600);
    let o = import(&d, home.path(), &[]);
    assert_eq!(o.status.code(), Some(0), "{}", all(&o));
    let t = out(&o);
    assert!(t.contains("skipped:"), "{t}");
    assert!(
        t.contains(&format!("{}: Vault token (no terminal", vt.display())),
        "{t}"
    );
    assert_eq!(fs::read_to_string(&vt).unwrap(), "hvs.skipvalue0005\n");
    assert!(names(&d).is_empty());
    assert!(!all(&o).contains("skipvalue0005"));
}

#[test]
fn symlinked_source_not_followed() {
    let d = admin();
    let home = scratch();
    let elsewhere = scratch();
    let target = put(elsewhere.path(), "real", "hvs.linkvalue0006\n", 0o600);
    let link = home.path().join(".vault-token");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let o = import(&d, home.path(), &["--yes-to", link.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0), "{}", all(&o));
    assert!(out(&o).contains("not followed"), "{}", out(&o));
    assert_eq!(fs::read_to_string(&target).unwrap(), "hvs.linkvalue0006\n");
    assert!(fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(names(&d).is_empty());
}

#[test]
fn non_admin_refused_before_reading() {
    let d = TestDaemon::start(Opts::default());
    let home = scratch();
    let vt = put(home.path(), ".vault-token", "hvs.nonadmin0007\n", 0o600);
    let o = import(&d, home.path(), &["--yes-to", vt.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2), "{}", all(&o));
    assert!(all(&o).contains("[admin] groups"), "{}", all(&o));
    assert_eq!(fs::read_to_string(&vt).unwrap(), "hvs.nonadmin0007\n");
}

fn restart_at(d: &mut TestDaemon, now: SystemTime) {
    let mut c = d.child.take().unwrap();
    let _ = c.kill();
    let _ = c.wait();
    let secs = now
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();
    d.spawn_and_wait_with(&[("SAIIFE_DAEMON_NOW", secs.as_str())]);
}

#[test]
fn backup_written_and_purged_after_7_days() {
    let mut d = admin();
    let home = scratch();
    let vt = put(home.path(), ".vault-token", "hvs.purgevalue0008\n", 0o600);
    let s = svc(&vt, "github");
    let o = import(
        &d,
        home.path(),
        &["--yes-to", vt.to_str().unwrap(), "--service", &s],
    );
    assert_eq!(o.status.code(), Some(0), "{}", all(&o));
    assert_eq!(fs::read_to_string(&vt).unwrap(), "");
    let b = backups(&d);
    assert_eq!(b.len(), 1);
    assert_eq!(fs::read_to_string(&b[0]).unwrap(), "hvs.purgevalue0008\n");

    let day = Duration::from_secs(24 * 3600);
    restart_at(&mut d, SystemTime::now() + 6 * day);
    assert_eq!(backups(&d), b, "kept for 7 days");
    restart_at(&mut d, SystemTime::now() + 8 * day);
    assert!(backups(&d).is_empty(), "purged after 7 days");
}

#[test]
fn value_never_printed() {
    let d = admin();
    let home = scratch();
    let proj = home.path().join("proj");
    let env = put(
        &proj,
        ".env.local",
        "API_KEY=envvalue0009\nSHOPIFY_TOKEN='shpat_value0009'\n",
        0o600,
    );
    let creds = put(
        home.path(),
        ".git-credentials",
        "https://bob:gitvalue0009@example.com\n",
        0o600,
    );
    let npm = put(
        home.path(),
        ".npmrc",
        "registry=https://r.example\n//r.example/:_authToken=npmvalue0009\n",
        0o600,
    );
    let gh = put(
        home.path(),
        ".config/gh/hosts.yml",
        "github.com:\n    user: bob\n    oauth_token: ghovalue0009\n",
        0o600,
    );
    let originals: Vec<Vec<u8>> = [&env, &creds, &npm, &gh]
        .iter()
        .map(|p| fs::read(p).unwrap())
        .collect();
    let mut args = vec!["--project".to_string(), proj.display().to_string()];
    for p in [&env, &creds, &npm, &gh] {
        args.push("--yes-to".into());
        args.push(p.display().to_string());
    }
    for (p, s) in [(&env, "shopify"), (&creds, "github"), (&npm, "hubspot")] {
        args.push("--service".into());
        args.push(svc(p, s));
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let o = import(&d, home.path(), &args);
    assert_eq!(o.status.code(), Some(0), "{}", all(&o));
    assert_eq!(names(&d).len(), 5, "{}", all(&o));
    assert_eq!(fs::read_to_string(&env).unwrap(), "");
    assert_eq!(
        fs::read_to_string(&npm).unwrap(),
        "registry=https://r.example\n"
    );
    assert_eq!(
        fs::read_to_string(&gh).unwrap(),
        "github.com:\n    user: bob\n"
    );
    assert!(out(&o).contains("next: saiife connect shopify --secret"));

    let daemon_stderr = d.stderr_text();
    let seen = format!("{}{}", all(&o), audit_text(&d));
    for v in [
        "envvalue0009",
        "shpat_value0009",
        "gitvalue0009",
        "npmvalue0009",
        "ghovalue0009",
    ] {
        assert!(!seen.contains(v), "{v} leaked");
        assert!(!daemon_stderr.contains(v), "{v} in the daemon's stderr");
        assert!(!seen.contains(&b64(v.as_bytes())), "{v} leaked as base64");
    }
    for orig in &originals {
        assert!(!seen.contains(&b64(orig)), "a backup leaked as base64");
    }
}

#[test]
fn no_service_is_skipped_not_stored() {
    let d = admin();
    let home = scratch();
    let vt = put(home.path(), ".vault-token", "hvs.orphan0010\n", 0o600);
    let creds = put(
        home.path(),
        ".git-credentials",
        "https://bob:orphan0010b@github.com.evil.example\n",
        0o600,
    );
    let o = import(
        &d,
        home.path(),
        &[
            "--yes-to",
            vt.to_str().unwrap(),
            "--yes-to",
            creds.to_str().unwrap(),
        ],
    );
    assert_eq!(o.status.code(), Some(0), "{}", all(&o));
    let t = out(&o);
    for (p, what) in [(&vt, "Vault token"), (&creds, "git credential for")] {
        assert!(
            t.contains(&format!("{}: {what}", p.display()))
                && t.contains("(no known service; pass --service <path>=<service>)"),
            "{t}"
        );
    }
    assert!(names(&d).is_empty(), "never stored as unassigned");
    assert_eq!(fs::read_to_string(&vt).unwrap(), "hvs.orphan0010\n");
    assert!(backups(&d).is_empty());
}

#[test]
fn unknown_service_or_relative_path_refused() {
    let d = admin();
    let home = scratch();
    let vt = put(home.path(), ".vault-token", "hvs.badsvc0011\n", 0o600);
    let bad = svc(&vt, "unassigned");
    let o = import(&d, home.path(), &["--service", &bad]);
    assert_eq!(o.status.code(), Some(2), "{}", all(&o));
    assert!(
        all(&o).contains("unknown service unassigned"),
        "{}",
        all(&o)
    );
    let o = import(&d, home.path(), &["--yes-to", ".vault-token"]);
    assert_eq!(o.status.code(), Some(2), "{}", all(&o));
    assert!(all(&o).contains("--yes-to takes an absolute path"));
    assert_eq!(fs::read_to_string(&vt).unwrap(), "hvs.badsvc0011\n");
    assert!(names(&d).is_empty());
}

#[test]
fn file_of_another_uid_refused() {
    let d = admin();
    let home = scratch();
    let vt = put(home.path(), ".vault-token", "hvs.otheruid0012\n", 0o600);
    let s = svc(&vt, "github");
    // Test seam: the agent user is someone else, so the file is not theirs.
    let other = (common::daemon::own_uid() + 1).to_string();
    let o = import_env(
        &d,
        home.path(),
        &["--yes-to", vt.to_str().unwrap(), "--service", &s],
        &[("SAIIFE_IMPORT_TARGET_UID", other.as_str())],
    );
    assert_eq!(o.status.code(), Some(2), "{}", all(&o));
    let want = format!(
        "{}: not imported: owned by uid {}; remove by hand",
        vt.display(),
        common::daemon::own_uid()
    );
    assert!(out(&o).contains(&want), "{}", all(&o));
    assert_eq!(fs::read_to_string(&vt).unwrap(), "hvs.otheruid0012\n");
    assert!(names(&d).is_empty());
    assert!(backups(&d).is_empty());
}

#[test]
fn hardlinked_file_refused() {
    let d = admin();
    let home = scratch();
    let vt = put(home.path(), ".vault-token", "hvs.hardlink0013\n", 0o600);
    let twin = home.path().join("twin");
    fs::hard_link(&vt, &twin).unwrap();
    let s = svc(&vt, "github");
    let o = import(
        &d,
        home.path(),
        &["--yes-to", vt.to_str().unwrap(), "--service", &s],
    );
    assert_eq!(o.status.code(), Some(2), "{}", all(&o));
    assert!(
        out(&o).contains("not imported: has other links; remove by hand"),
        "{}",
        all(&o)
    );
    assert_eq!(fs::read_to_string(&twin).unwrap(), "hvs.hardlink0013\n");
    assert!(names(&d).is_empty());
}

#[test]
fn symlinked_project_root_refused() {
    let d = admin();
    let home = scratch();
    let outside = scratch();
    let real = outside.path().join("real");
    let env = put(&real, ".env", "GITHUB_TOKEN=ghp_rootlink0014\n", 0o600);
    let link = outside.path().join("proj");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let linked_env = link.join(".env");
    let o = import(
        &d,
        home.path(),
        &[
            "--project",
            link.to_str().unwrap(),
            "--yes-to",
            linked_env.to_str().unwrap(),
        ],
    );
    assert_eq!(o.status.code(), Some(2), "{}", all(&o));
    assert!(
        all(&o).contains("is a symlink; give the real path"),
        "{}",
        all(&o)
    );
    assert_eq!(
        fs::read_to_string(&env).unwrap(),
        "GITHUB_TOKEN=ghp_rootlink0014\n"
    );
    assert!(names(&d).is_empty());
}

#[test]
fn unrecorded_add_reports_stored_and_leaves_the_file() {
    let mut d = TestDaemon::prepare(&admin_opts());
    d.spawn_and_wait_with(&[("SAIIFE_DAEMON_FAULT", "secret_record")]);
    let home = scratch();
    let creds = put(
        home.path(),
        ".git-credentials",
        "https://bob:ghp_unrec0015@github.com\n",
        0o600,
    );
    let o = import(&d, home.path(), &["--yes-to", creds.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2), "{}", all(&o));
    let t = out(&o);
    let name = format!("{}-git-github.com", own_user());
    assert!(
        t.contains(&format!("{}: stored {name}, but", creds.display()))
            && t.contains("audit record failed")
            && t.contains("the file is not changed, remove it by hand"),
        "{t}"
    );
    assert!(!t.contains("not stored"), "{t}");
    assert_eq!(
        fs::read_to_string(&creds).unwrap(),
        "https://bob:ghp_unrec0015@github.com\n"
    );
}
