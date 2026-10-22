//! Pins the managed agent config fixtures to spec section 8.3.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use toml_edit::DocumentMut;

const BIN: &str = "/opt/saiife/bin/saiife ";

fn read(rel: &str) -> String {
    let p: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests/fixtures/managed", rel]
        .iter()
        .collect();
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn json(rel: &str) -> Value {
    serde_json::from_str(&read(rel)).expect("valid json")
}

fn toml(rel: &str) -> DocumentMut {
    read(rel).parse::<DocumentMut>().expect("valid toml")
}

#[test]
fn claude_managed_matches_spec() {
    let v = json("claude/50-saiife.json");
    let pre = &v["hooks"]["PreToolUse"][0];
    assert_eq!(pre["matcher"], "*");
    let h = &pre["hooks"][0];
    assert_eq!(
        h["command"],
        "/opt/saiife/bin/saiife check --managed --hook-exit --agent claude"
    );
    assert_eq!(h["timeout"], 10);
    assert_eq!(h["onFailure"], "block");
    let cc = &v["hooks"]["ConfigChange"][0]["hooks"][0];
    assert!(cc["command"]
        .as_str()
        .unwrap()
        .ends_with("--agent claude --event config-change"));
    assert_eq!(cc["timeout"], 10);
    assert_eq!(cc["onFailure"], "block");
    assert_eq!(v["disableAllHooks"], false);
    assert!(v.get("allowManagedHooksOnly").is_none());
}

#[test]
fn codex_managed_matches_spec() {
    let d = toml("codex/requirements.toml");
    assert_eq!(d["features"]["hooks"].as_bool(), Some(true));
    let pre = d["hooks"]["PreToolUse"]
        .as_array_of_tables()
        .expect("array of tables")
        .get(0)
        .unwrap();
    assert_eq!(pre["matcher"].as_str(), Some(".*"));
    let h = pre["hooks"]
        .as_array_of_tables()
        .expect("array of tables")
        .get(0)
        .unwrap();
    assert_eq!(h["type"].as_str(), Some("command"));
    assert_eq!(
        h["command"].as_str(),
        Some("/opt/saiife/bin/saiife check --managed --hook-exit --agent codex")
    );
    assert_eq!(h["timeout"].as_integer(), Some(10));
    assert_eq!(h["statusMessage"].as_str(), Some("saiife guard (locked)"));
}

#[test]
fn gemini_managed_matches_spec() {
    let v = json("gemini/settings.json");
    let group = &v["hooks"]["BeforeTool"][0];
    assert!(group.get("matcher").is_none());
    let h = &group["hooks"][0];
    assert_eq!(
        h["command"],
        "/opt/saiife/bin/saiife check --managed --hook-exit --agent gemini"
    );
    assert_eq!(h["name"], "saiife");
    assert_eq!(h["timeout"], 10000);
}

fn collect_commands(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                if k == "command" {
                    out.push(x.as_str().expect("command is a string").to_string());
                } else {
                    collect_commands(x, out);
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|x| collect_commands(x, out)),
        _ => {}
    }
}

#[test]
fn every_managed_command_is_absolute() {
    let mut cmds = Vec::new();
    collect_commands(&json("claude/50-saiife.json"), &mut cmds);
    collect_commands(&json("gemini/settings.json"), &mut cmds);
    let codex = read("codex/requirements.toml");
    for line in codex.lines().filter(|l| l.starts_with("command")) {
        cmds.push(line.split('"').nth(1).expect("quoted").to_string());
    }
    assert_eq!(cmds.len(), 4);
    for c in cmds {
        assert!(c.starts_with(BIN), "not absolute: {c}");
    }
}

// ------------------------------------------------- managed writers (plan 9b)

use saiife_agents::{claude, codex, gemini, is_saiife_command, Change};
use std::path::Path;

fn json_file(p: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap()
}

/// Same parsed value: comments, decor and layout are ignored.
fn toml_eq(a: &str, b: &str) -> bool {
    fn plain(t: &toml_edit::Table) -> Value {
        Value::Object(t.iter().map(|(k, v)| (k.to_string(), item(v))).collect())
    }
    fn item(i: &toml_edit::Item) -> Value {
        match i {
            toml_edit::Item::Value(v) => val(v),
            toml_edit::Item::Table(t) => plain(t),
            toml_edit::Item::ArrayOfTables(a) => Value::Array(a.iter().map(plain).collect()),
            toml_edit::Item::None => Value::Null,
        }
    }
    fn val(v: &toml_edit::Value) -> Value {
        use toml_edit::Value as T;
        match v {
            T::String(s) => Value::String(s.value().clone()),
            T::Integer(i) => Value::from(*i.value()),
            T::Float(f) => Value::from(*f.value()),
            T::Boolean(b) => Value::Bool(*b.value()),
            T::Datetime(d) => Value::String(d.value().to_string()),
            T::Array(a) => Value::Array(a.iter().map(val).collect()),
            T::InlineTable(t) => {
                Value::Object(t.iter().map(|(k, v)| (k.to_string(), val(v))).collect())
            }
        }
    }
    let pa = plain(a.parse::<DocumentMut>().unwrap().as_table());
    let pb = plain(b.parse::<DocumentMut>().unwrap().as_table());
    pa == pb
}

#[test]
fn claude_managed_settings_is_fixture() {
    assert_eq!(claude::managed_settings(), read("claude/50-saiife.json"));
}

#[test]
fn codex_fresh_file_matches_fixture() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("requirements.toml");
    assert!(matches!(
        codex::install_managed(&f).unwrap(),
        Change::Created { .. }
    ));
    let got = fs::read_to_string(&f).unwrap();
    assert!(
        toml_eq(&got, &read("codex/requirements.toml")),
        "got:\n{got}"
    );
    assert!(codex::managed_entry(&f).unwrap().is_some());
}

#[test]
fn gemini_fresh_file_matches_fixture() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("settings.json");
    assert!(matches!(
        gemini::install_managed(&f).unwrap(),
        Change::Created { .. }
    ));
    assert_eq!(json_file(&f), json("gemini/settings.json"));
    assert!(gemini::managed_entry(&f).unwrap().is_some());
}

const ADMIN_CODEX: &str = r#"# company policy
[features]
web_search = true

[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/usr/local/bin/company-audit"
"#;

#[test]
fn codex_requirements_keeps_admin_entries() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("requirements.toml");
    fs::write(&f, ADMIN_CODEX).unwrap();
    assert_eq!(codex::install_managed(&f).unwrap(), Change::Updated);
    let text = fs::read_to_string(&f).unwrap();
    assert!(text.starts_with("# company policy\n"), "{text}");
    let d = text.parse::<DocumentMut>().unwrap();
    assert_eq!(d["features"]["web_search"].as_bool(), Some(true));
    assert_eq!(d["features"]["hooks"].as_bool(), Some(true));
    let groups = d["hooks"]["PreToolUse"].as_array_of_tables().unwrap();
    assert_eq!(groups.len(), 2);
    let admin = groups.get(0).unwrap()["hooks"]
        .as_array_of_tables()
        .unwrap();
    assert_eq!(
        admin.get(0).unwrap()["command"].as_str(),
        Some("/usr/local/bin/company-audit")
    );
    let ours = groups.get(1).unwrap();
    assert_eq!(ours["matcher"].as_str(), Some(".*"));
    let h = ours["hooks"].as_array_of_tables().unwrap().get(0).unwrap();
    assert_eq!(
        h["command"].as_str(),
        Some("/opt/saiife/bin/saiife check --managed --hook-exit --agent codex")
    );
    assert_eq!(h["statusMessage"].as_str(), Some("saiife guard (locked)"));
    assert_eq!(h["timeout"].as_integer(), Some(10));

    assert_eq!(codex::remove_managed(&f).unwrap(), Change::Updated);
    let back = fs::read_to_string(&f).unwrap();
    assert!(toml_eq(&back, ADMIN_CODEX), "back:\n{back}");
    assert_eq!(codex::managed_entry(&f).unwrap(), None);
}

#[test]
fn codex_admin_hooks_true_is_kept_on_remove() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("requirements.toml");
    let admin = "[features]\nhooks = true\n";
    fs::write(&f, admin).unwrap();
    codex::install_managed(&f).unwrap();
    codex::remove_managed(&f).unwrap();
    assert!(toml_eq(&fs::read_to_string(&f).unwrap(), admin));
}

#[test]
fn codex_tampered_features_hooks_changes_the_fingerprint() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("requirements.toml");
    codex::install_managed(&f).unwrap();
    let before = codex::managed_entry(&f).unwrap().unwrap();
    let text = fs::read_to_string(&f)
        .unwrap()
        .replacen("hooks = true", "hooks = false", 1);
    fs::write(&f, text).unwrap();
    assert_ne!(codex::managed_entry(&f).unwrap().unwrap(), before);
    // Install repairs it.
    assert_eq!(codex::install_managed(&f).unwrap(), Change::Updated);
    assert_eq!(codex::managed_entry(&f).unwrap().unwrap(), before);
}

const ADMIN_GEMINI: &str = r#"{
  "general": {
    "vimMode": true
  },
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "write_file",
        "hooks": [
          {
            "type": "command",
            "command": "/usr/local/bin/fmt-check",
            "name": "fmt"
          }
        ]
      }
    ]
  }
}
"#;

#[test]
fn gemini_settings_keeps_admin_entries() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("settings.json");
    fs::write(&f, ADMIN_GEMINI).unwrap();
    assert_eq!(gemini::install_managed(&f).unwrap(), Change::Updated);
    let v = json_file(&f);
    assert_eq!(v["general"]["vimMode"], true);
    let groups = v["hooks"]["BeforeTool"].as_array().unwrap();
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0]["hooks"][0]["name"], "fmt");
    assert_eq!(
        groups[1],
        json("gemini/settings.json")["hooks"]["BeforeTool"][0]
    );
    assert_eq!(gemini::remove_managed(&f).unwrap(), Change::Updated);
    assert_eq!(fs::read_to_string(&f).unwrap(), ADMIN_GEMINI);
    assert_eq!(gemini::managed_entry(&f).unwrap(), None);
}

#[test]
fn install_managed_twice_is_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let c = dir.path().join("requirements.toml");
    let g = dir.path().join("settings.json");
    codex::install_managed(&c).unwrap();
    gemini::install_managed(&g).unwrap();
    let (c1, g1) = (fs::read(&c).unwrap(), fs::read(&g).unwrap());
    let (ce, ge) = (
        codex::managed_entry(&c).unwrap(),
        gemini::managed_entry(&g).unwrap(),
    );
    assert_eq!(codex::install_managed(&c).unwrap(), Change::Unchanged);
    assert_eq!(gemini::install_managed(&g).unwrap(), Change::Unchanged);
    assert_eq!(fs::read(&c).unwrap(), c1);
    assert_eq!(fs::read(&g).unwrap(), g1);
    assert_eq!(codex::managed_entry(&c).unwrap(), ce);
    assert_eq!(gemini::managed_entry(&g).unwrap(), ge);
}

#[test]
fn managed_writers_write_0644_and_refuse_symlinks() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let c = dir.path().join("requirements.toml");
    codex::install_managed(&c).unwrap();
    let mode = fs::metadata(&c).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o644);
    let real = dir.path().join("real.json");
    fs::write(&real, "{}").unwrap();
    let link = dir.path().join("settings.json");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(gemini::install_managed(&link).is_err());
    assert_eq!(fs::read_to_string(&real).unwrap(), "{}");
    let tlink = dir.path().join("req2.toml");
    std::os::unix::fs::symlink(&c, &tlink).unwrap();
    assert!(codex::remove_managed(&tlink).is_err());
}

#[test]
fn remove_managed_of_a_missing_file_is_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        codex::remove_managed(&dir.path().join("x.toml")).unwrap(),
        Change::Unchanged
    );
    assert_eq!(
        gemini::remove_managed(&dir.path().join("x.json")).unwrap(),
        Change::Unchanged
    );
    assert_eq!(
        codex::managed_entry(&dir.path().join("x.toml")).unwrap(),
        None
    );
}

#[test]
fn is_saiife_command_accepts_managed_path() {
    for a in saiife_agents::Agent::ALL {
        assert!(is_saiife_command(&a.managed_command()));
    }
    assert!(is_saiife_command(
        "/opt/saiife/bin/saiife check --managed --hook-exit --agent claude --event config-change"
    ));
    assert!(!is_saiife_command("/opt/saiife/bin/saiife daemon --system"));
}

/// install_managed then remove_managed gives back `original`'s parsed value.
fn codex_round_trip(original: &str) -> (String, String) {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("requirements.toml");
    fs::write(&f, original).unwrap();
    codex::install_managed(&f).unwrap();
    let installed = fs::read_to_string(&f).unwrap();
    let d = installed.parse::<DocumentMut>().unwrap();
    assert_eq!(d["features"]["hooks"].as_bool(), Some(true), "{installed}");
    codex::remove_managed(&f).unwrap();
    let back = fs::read_to_string(&f).unwrap();
    assert!(
        toml_eq(&back, original),
        "original:\n{original}\nback:\n{back}"
    );
    (installed, back)
}

#[test]
fn codex_prior_hooks_false_is_restored() {
    let (_, back) = codex_round_trip("[features]\nhooks = false\nweb_search = true\n");
    assert!(back.contains("hooks = false"), "{back}");
}

#[test]
fn codex_prior_hooks_other_value_is_restored() {
    codex_round_trip("[features]\nhooks = \"maybe\"\n");
    codex_round_trip("[features]\nhooks = 0 # admin note\n");
}

#[test]
fn codex_prior_admin_comment_is_kept() {
    let (installed, back) = codex_round_trip("[features]\nhooks = false # keep me\n");
    assert!(installed.contains("# keep me"), "{installed}");
    assert!(back.contains("hooks = false # keep me"), "{back}");
}

#[test]
fn codex_inline_features_round_trip() {
    let (installed, _) = codex_round_trip("features = { web_search = true }\n");
    assert!(
        installed.contains("# saiife: hooks was absent"),
        "{installed}"
    );
    codex_round_trip("features = { web_search = true, hooks = false }\n");
}

#[test]
fn codex_features_table_added_is_dropped_again() {
    // No [features] before: none after (the hooks group is the only other
    // content, so the file is empty again).
    let (_, back) = codex_round_trip("model = \"x\"\n");
    assert!(!back.contains("features"), "{back}");
    // An admin's empty [features] stays.
    let (_, back) = codex_round_trip("[features]\n");
    assert!(back.contains("[features]"), "{back}");
}

#[test]
fn codex_reinstall_after_tamper_keeps_the_first_prior_value() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("requirements.toml");
    let original = "[features]\nweb_search = true\n";
    fs::write(&f, original).unwrap();
    codex::install_managed(&f).unwrap();
    // Someone turns hooks off but leaves saiife's comment.
    let t = fs::read_to_string(&f)
        .unwrap()
        .replacen("hooks = true", "hooks = false", 1);
    fs::write(&f, t).unwrap();
    codex::install_managed(&f).unwrap();
    codex::remove_managed(&f).unwrap();
    assert!(toml_eq(&fs::read_to_string(&f).unwrap(), original));
}
