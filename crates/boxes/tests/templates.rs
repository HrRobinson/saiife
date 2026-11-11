#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::path::Path;

use saiife_boxes::template::{
    builtin, load_dir, parse, AgentKind, EgressRule, ImageRef, Login, Size, Trust,
};
use saiife_touch::TouchClass;

const FULL: &str = r#"
name = "rust"
description = "Rust box"
[agent]
kind = "claude-code"
command = ["claude", "--x"]
login = "subscription"
credential = "anthropic-sub"
credential_in_box = true
[image]
base = "base-0000000000000000000000000000000000000000000000000000000000000000"
[size]
vcpus = 4
mem_mib = 2048
mem_max_mib = 4096
disk_gib = 50
[egress]
allow = ["registry.npmjs.org", "*.crates.io:8443"]
[secrets]
names = ["npm-token"]
[rules]
profile = "strict"
[touch]
classes = ["land"]
[idle]
stop_after_mins = 30
"#;

const MIN: &str = "name = \"m\"\ndescription = \"d\"\n[agent]\nkind = \"claude-code\"\ncommand = [\"claude\"]\nlogin = \"api-key\"\ncredential = \"anthropic\"\n";

fn with(extra: &str) -> String {
    format!("{MIN}{extra}")
}

#[test]
fn builtin_claude_code() {
    let b = builtin();
    assert_eq!(b.len(), 1);
    let t = &b[0];
    assert_eq!(t.name, "claude-code");
    assert_eq!(t.agent, AgentKind::ClaudeCode);
    assert_eq!(t.login, Login::ApiKey);
    assert_eq!(t.credential, "anthropic");
    assert!(!t.credential_in_box);
    assert_eq!(t.size, Size::default());
    assert!(t.egress.is_empty() && t.secrets.is_empty());
    assert_eq!(t.touch, vec![TouchClass::Land, TouchClass::PushProtected]);
    let w = t.wire();
    assert!(!w.has_secrets && !w.has_egress);
}

#[test]
fn full_file_roundtrip() {
    let t = parse("rust", FULL).unwrap();
    assert_eq!(t.command, vec!["claude", "--x"]);
    assert_eq!(t.login, Login::Subscription);
    assert!(matches!(t.image, ImageRef::Pinned(_)));
    assert_eq!(
        t.size,
        Size {
            vcpus: 4,
            mem_mib: 2048,
            mem_max_mib: 4096,
            disk_gib: 50
        }
    );
    assert_eq!(
        t.egress,
        vec![
            EgressRule {
                host: "registry.npmjs.org".into(),
                port: 443
            },
            EgressRule {
                host: "*.crates.io".into(),
                port: 8443
            }
        ]
    );
    assert_eq!(t.secrets, vec!["npm-token"]);
    assert_eq!(t.rules_profile, "strict");
    assert_eq!(t.touch, vec![TouchClass::Land]);
    assert_eq!(t.idle_stop_mins, 30);
    let w = t.wire();
    assert!(w.has_secrets && w.has_egress);
}

#[test]
fn defaults_apply() {
    let t = parse("m", MIN).unwrap();
    assert_eq!(t.image, ImageRef::Default);
    assert_eq!(t.size, Size::default());
    assert!(t.egress.is_empty() && t.secrets.is_empty());
    assert_eq!(t.rules_profile, "default");
    assert_eq!(t.touch, vec![TouchClass::Land, TouchClass::PushProtected]);
    assert_eq!(t.idle_stop_mins, 120);
}

#[test]
fn credential_in_box_defaults_false() {
    assert!(!parse("m", MIN).unwrap().credential_in_box);
}

#[test]
fn credential_in_box_parses() {
    let text = MIN.replace(
        "credential = \"anthropic\"",
        "credential = \"anthropic\"\ncredential_in_box = true",
    );
    assert!(parse("m", &text).unwrap().credential_in_box);
}

#[test]
fn unknown_key_is_refused() {
    assert!(parse("m", &with("bogus = 1\n")).is_err());
    assert!(parse("m", &with("[size]\nbogus = 1\n")).is_err());
}

#[test]
fn stem_must_match_name() {
    assert!(parse("other", MIN).is_err());
}

#[test]
fn size_bounds() {
    let s = |body: &str| parse("m", &with(&format!("[size]\n{body}")));
    assert!(s("vcpus = 0").is_err());
    assert!(s("mem_mib = 4096\nmem_max_mib = 2048").is_err());
    assert!(s("disk_gib = 2048").is_err());
    assert!(s("disk_gib = 9").is_err());
    assert!(s("disk_gib = 10").is_ok());
    assert!(s("vcpus = 33").is_err());
    assert!(s("vcpus = 32").is_ok());
    assert!(s("mem_mib = 511\nmem_max_mib = 8192").is_err());
    assert!(s("mem_mib = 512\nmem_max_mib = 8192").is_ok());
}

#[test]
fn name_rule() {
    let n = |name: &str| parse(name, &MIN.replace("\"m\"", &format!("\"{name}\"")));
    assert!(n("a_b").is_err());
    assert!(n(&"a".repeat(40)).is_ok());
    assert!(n(&"a".repeat(41)).is_err());
    assert!(n("-a").is_err());
}

#[test]
fn egress_rules() {
    let e = |h: &str| parse("m", &with(&format!("[egress]\nallow = [\"{h}\"]\n")));
    let ok = e("registry.npmjs.org").unwrap();
    assert_eq!(ok.egress[0].port, 443);
    assert!(e("*.crates.io:443").is_ok());
    for bad in [
        "*",
        "https://x.org",
        "x.org/path",
        "X.org",
        "a..b",
        "x.org:0",
        "x.org:99999",
        "",
    ] {
        assert!(e(bad).is_err(), "{bad}");
    }
}

#[test]
fn unknown_touch_class_is_refused() {
    assert!(parse("m", &with("[touch]\nclasses = [\"nope\"]\n")).is_err());
}

#[test]
fn pinned_image_must_be_hex() {
    let img = |b: &str| parse("m", &with(&format!("[image]\nbase = \"{b}\"\n")));
    assert!(img(&format!("base-{}", "a".repeat(63))).is_err());
    assert!(img(&format!("base-{}", "A".repeat(64))).is_err());
    assert!(img(&format!("base-{}", "a".repeat(64))).is_ok());
}

#[cfg(unix)]
fn own_uid(dir: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(dir).unwrap().uid()
}

#[cfg(unix)]
#[test]
fn bad_files_are_skipped_others_load() {
    let d = tempfile::tempdir().unwrap();
    let good = MIN.replace("\"m\"", "\"good\"");
    fs::write(d.path().join("good.toml"), good).unwrap();
    fs::write(
        d.path().join("bad1.toml"),
        with("bogus = 1\n").replace("\"m\"", "\"bad1\""),
    )
    .unwrap();
    fs::write(d.path().join("bad2.toml"), vec![b'#'; 1_000_000]).unwrap();
    fs::write(d.path().join("notes.txt"), "hi").unwrap();
    let (ts, ws) = load_dir(d.path(), Trust::OwnedBy(own_uid(d.path())));
    let names: Vec<_> = ts.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, ["claude-code", "good"]);
    assert_eq!(ws.len(), 2);
    assert!(ws.iter().any(|w| w.file.ends_with("bad1.toml")));
    assert!(ws.iter().any(|w| w.file.ends_with("bad2.toml")));
}

#[cfg(unix)]
#[test]
fn file_replaces_builtin() {
    let d = tempfile::tempdir().unwrap();
    let text = MIN
        .replace("\"m\"", "\"claude-code\"")
        .replace("\"d\"", "\"mine\"");
    fs::write(d.path().join("claude-code.toml"), text).unwrap();
    let (ts, ws) = load_dir(d.path(), Trust::OwnedBy(own_uid(d.path())));
    assert!(ws.is_empty(), "{ws:?}");
    assert_eq!(ts.len(), 1);
    assert_eq!(ts[0].description, "mine");
}

#[test]
fn missing_dir_is_builtins() {
    let d = tempfile::tempdir().unwrap();
    let (ts, ws) = load_dir(&d.path().join("nope"), Trust::RootOwned);
    assert_eq!(ts, builtin());
    assert!(ws.is_empty());
}

#[cfg(unix)]
#[test]
fn locked_mode_trusts_only_root_owned_files() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let uid = own_uid(d.path());
    let f = d.path().join("m.toml");
    fs::write(&f, MIN).unwrap();
    let reason = |t: Trust| {
        let (_, ws) = load_dir(d.path(), t);
        ws.into_iter().next().map(|w| w.reason)
    };
    if uid != 0 {
        assert!(reason(Trust::RootOwned)
            .unwrap()
            .contains("not owned by root"));
    }
    assert_eq!(reason(Trust::OwnedBy(uid)), None);
    fs::set_permissions(&f, fs::Permissions::from_mode(0o664)).unwrap();
    assert!(reason(Trust::OwnedBy(uid))
        .unwrap()
        .contains("group- or world-writable"));
    fs::remove_file(&f).unwrap();
    fs::write(d.path().join("target"), MIN).unwrap();
    std::os::unix::fs::symlink(d.path().join("target"), &f).unwrap();
    let (_, ws) = load_dir(d.path(), Trust::OwnedBy(uid));
    assert!(ws
        .iter()
        .any(|w| w.file.ends_with("m.toml") && w.reason.contains("symlink")));
}

#[cfg(unix)]
#[test]
fn non_regular_entries_are_skipped_before_opening() {
    let d = tempfile::tempdir().unwrap();
    fs::create_dir(d.path().join("d.toml")).unwrap();
    let (ts, ws) = load_dir(d.path(), Trust::OwnedBy(own_uid(d.path())));
    assert_eq!(ts, builtin());
    assert_eq!(ws.len(), 1);
    assert!(ws[0].reason.contains("not a regular file"), "{ws:?}");
}
