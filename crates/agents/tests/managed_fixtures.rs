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
