//! Claude Code: `PreToolUse` hook in `.claude/settings.json`
//! (contract: docs/superpowers/research/2026-10-13-claude-code-hooks.md).

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::json_hooks::JsonHooks;
use crate::{Agent, AgentError, Change, HookBlocker};

pub const SETTINGS_REL: &str = ".claude/settings.json";

/// Shell (Bash and, on Windows, PowerShell), read and write tools (spec
/// §5.2). Only `[A-Za-z0-9_|]`, so Claude Code reads it as an exact list of
/// tool names. The matcher is the same on every platform.
pub const MATCHER: &str = "Bash|PowerShell|Read|Grep|Glob|LS|Write|Edit|MultiEdit|NotebookEdit";

/// The matcher before the `PowerShell` tool was added (plan 3 to plan 19a).
/// A project hooked by it is upgraded by `saiife init`.
pub const MATCHER_V2: &str = "Bash|Read|Grep|Glob|LS|Write|Edit|MultiEdit|NotebookEdit";

/// The matcher plan 2's saiife wrote. A project hooked by it is upgraded by
/// running `saiife init` again (`status` reports the entry as out of date).
pub const MATCHER_V1: &str = "Bash|Read|Grep|Write|Edit|MultiEdit|NotebookEdit";

/// Whether `m` is a matcher an older saiife wrote, which lacks the
/// `PowerShell` tool.
pub fn matcher_is_outdated(m: &str) -> bool {
    m == MATCHER_V1 || m == MATCHER_V2
}

/// Seconds. No `onFailure: "block"`: v1 developer mode fails open (spec §1.2
/// rule 4).
pub const TIMEOUT_SECS: u64 = 10;

pub const NEXT_STEP: &str = "Claude Code holds back project hooks until you accept the workspace trust prompt: start `claude` in this folder and accept it. `/hooks` shows the saiife hook.";

/// Managed-settings directories (Linux, macOS). Read-only checks.
#[cfg(not(windows))]
pub const MANAGED_DIRS: &[&str] = &[
    "/etc/claude-code",
    "/Library/Application Support/ClaudeCode",
];

/// Managed-settings directory on Windows (`managed-settings.json` inside).
#[cfg(windows)]
pub const MANAGED_DIRS: &[&str] = &[WINDOWS_MANAGED_DIR];

/// Claude Code's managed-settings directory on Windows (spec §5.3a).
pub const WINDOWS_MANAGED_DIR: &str = r"C:\Program Files\ClaudeCode";

/// The managed drop-in `/etc/claude-code/managed-settings.d/50-saiife.json`
/// (locked mode), byte for byte spec §8.3.
const MANAGED_SETTINGS: &str = r#"{
  "hooks": {
    "PreToolUse": [
      { "matcher": "*",
        "hooks": [ { "type": "command",
                     "command": "/opt/saiife/bin/saiife check --managed --hook-exit --agent claude",
                     "timeout": 10, "onFailure": "block" },
                   { "type": "http",
                     "url": "http://127.0.0.1:7433/v1/cosign/claude",
                     "timeout": 10, "onFailure": "block" } ] }
    ],
    "ConfigChange": [
      { "hooks": [ { "type": "command",
                     "command": "/opt/saiife/bin/saiife check --managed --hook-exit --agent claude --event config-change",
                     "timeout": 10, "onFailure": "block" } ] }
    ]
  },
  "allowedHttpHookUrls": ["http://127.0.0.1:7433/*"],
  "disableAllHooks": false
}
"#;

/// Where the drop-in's second `PreToolUse` hook posts: the saiife daemon's co-signer on
/// loopback (plan 20). It answers deny unless the command hook recorded an allow for the
/// same call, so a killed hook (exit 0 forged by `TerminateProcess`) is still a deny.
pub const COSIGN_URL: &str = "http://127.0.0.1:7433/v1/cosign/claude";

/// The drop-in's `allowedHttpHookUrls` entry. The lists merge across settings files, so a
/// user's own list cannot skip the co-signer.
pub const COSIGN_URL_PATTERN: &str = "http://127.0.0.1:7433/*";

/// The `agents.claude.policy` failure for a drop-in without the co-signer.
pub const COSIGN_MISSING_TEXT: &str =
    "the Claude Code drop-in has no saiife co-signer hook; run saiife system install";

/// Whether a Claude Code drop-in carries the co-signer: a `PreToolUse` hook of type `http`
/// at [`COSIGN_URL`] with `onFailure: "block"`, and [`COSIGN_URL_PATTERN`] in
/// `allowedHttpHookUrls`. Text that is not JSON carries nothing.
pub fn carries_cosign(text: &str) -> bool {
    let Ok(v) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    cosign_in(v.get("allowedHttpHookUrls"), &v["hooks"])
}

/// [`carries_cosign`] on a parsed file: its `allowedHttpHookUrls` and `hooks` values.
fn cosign_in(allowed: Option<&Value>, hooks: &Value) -> bool {
    let listed = allowed
        .and_then(Value::as_array)
        .is_some_and(|l| l.iter().any(|u| u == COSIGN_URL_PATTERN));
    let hooked = hooks["PreToolUse"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| e.get("hooks")?.as_array())
        .flatten()
        .any(|h| h["type"] == "http" && h["url"] == COSIGN_URL && h["onFailure"] == "block");
    listed && hooked
}

/// The whole managed drop-in saiife writes for Claude Code (spec §8.3).
pub fn managed_settings() -> &'static str {
    MANAGED_SETTINGS
}

/// [`managed_settings`] for a platform. On Windows only the binary path
/// differs (spec W9), so the two files differ in the command alone.
pub fn managed_settings_for(windows: bool) -> String {
    if windows {
        MANAGED_SETTINGS.replace(crate::UNIX_BINARY, crate::WINDOWS_BINARY)
    } else {
        MANAGED_SETTINGS.to_string()
    }
}

/// Where Claude Code's Windows policy lives (spec W24).
pub const HKLM_POLICY_KEY: &str = r"SOFTWARE\Policies\ClaudeCode";
/// The value under [`HKLM_POLICY_KEY`] that holds the settings JSON.
pub const HKLM_POLICY_VALUE: &str = "Settings";

/// The `agents.claude.policy` failure (spec W24).
pub const HKLM_OVERRIDES_TEXT: &str = "HKLM\\SOFTWARE\\Policies\\ClaudeCode sets Claude Code's managed settings, so saiife's drop-in is ignored; add \"managedSourcesBehavior\": \"merge\" there, or put saiife's hooks in it";

/// The `agents.claude.policy` failure when a merged policy can still turn saiife's hooks off.
pub const HKLM_WEAKENS_HOOKS_TEXT: &str = "HKLM\\SOFTWARE\\Policies\\ClaudeCode merges with saiife's drop-in, but its disableAllHooks or hooks value can turn saiife's hooks off; remove it, or put saiife's hooks and its allowedHttpHookUrls entry in it";

/// What the HKLM `Settings` value does to saiife's drop-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HklmPolicy {
    /// No `Settings` value, or one with no policy key: Claude Code moves on
    /// to the files.
    Absent,
    /// A policy source that merges with the files.
    Merge,
    /// A policy source that replaces the files: the drop-in is ignored.
    Overrides,
    /// It merges, and holds a value that can turn saiife's hooks off.
    WeakensHooks,
}

/// A registry read that failed for a reason other than "not found".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HklmReadError;

/// What a registry read gives [`hklm_policy`]: the value, none, or an error.
pub type HklmRead = Result<Option<String>, HklmReadError>;

/// Keys that steer how sources combine and are not policy themselves.
const CONTROL_KEYS: &[&str] = &["managedSourcesBehavior", "wslInheritsWindowsSettings"];

/// Reads the policy through `reg(key, value)` (the registry read is the
/// caller's; on Windows see [`hklm_policy_live`]). A value that is not a
/// JSON object but is not empty counts as `Overrides`: it fails closed.
pub fn hklm_policy(reg: &dyn Fn(&str, &str) -> HklmRead) -> HklmPolicy {
    let text = match reg(HKLM_POLICY_KEY, HKLM_POLICY_VALUE) {
        Ok(Some(t)) => t,
        Ok(None) => return HklmPolicy::Absent,
        // Access denied, a value of the wrong type, any read error: the
        // policy may be there, so the drop-in may be ignored.
        Err(HklmReadError) => return HklmPolicy::Overrides,
    };
    if text.trim().is_empty() {
        return HklmPolicy::Absent;
    }
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&text) else {
        return HklmPolicy::Overrides;
    };
    if map.keys().all(|k| CONTROL_KEYS.contains(&k.as_str())) {
        return HklmPolicy::Absent;
    }
    if map.get("managedSourcesBehavior").and_then(Value::as_str) != Some("merge") {
        return HklmPolicy::Overrides;
    }
    if can_turn_hooks_off(&map) {
        HklmPolicy::WeakensHooks
    } else {
        HklmPolicy::Merge
    }
}

/// What in a merged policy could stop saiife's hooks. `disableAllHooks` set to anything but
/// `false`; and a `hooks` value that does not itself carry saiife's whole handlers and the
/// co-signer with its allow-list entry ([`carries_cosign`]), since how Claude Code merges
/// that key is not documented here and it may replace the files' value.
fn can_turn_hooks_off(policy: &serde_json::Map<String, Value>) -> bool {
    if policy
        .get("disableAllHooks")
        .is_some_and(|v| v != &Value::Bool(false))
    {
        return true;
    }
    policy.get("hooks").is_some_and(|h| {
        !carries_saiife_hooks(h) || !cosign_in(policy.get("allowedHttpHookUrls"), h)
    })
}

/// The fields of a handler that decide what runs and what a failure does: its type, its
/// command or URL, and `onFailure`.
fn handler_core(h: &Value) -> [&Value; 4] {
    [&h["type"], &h["command"], &h["url"], &h["onFailure"]]
}

/// A matcher that runs on every call: absent, empty or `*`.
fn matches_all(m: &Value) -> bool {
    m.is_null() || m == "" || m == "*"
}

/// `theirs` (one event's entries) has an entry whose matcher covers `matcher` and whose
/// handlers include `handler`, field for field ([`handler_core`]).
fn holds_handler(theirs: &Value, matcher: &Value, handler: &Value) -> bool {
    let want = handler_core(handler);
    theirs.as_array().into_iter().flatten().any(|e| {
        let m = &e["matcher"];
        let covers = if matches_all(matcher) {
            matches_all(m)
        } else {
            m == matcher
        };
        covers
            && e["hooks"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|h| handler_core(h) == want)
    })
}

/// Every handler of saiife's drop-in, in each of its events, under a matcher that covers
/// saiife's. A handler that keeps its command but drops `onFailure`, or a `hooks` value
/// without the co-signer's HTTP handler, does not carry them.
fn carries_saiife_hooks(theirs: &Value) -> bool {
    let Ok(ours) = serde_json::from_str::<Value>(&managed_settings_for(true)) else {
        return false;
    };
    let Some(ours) = ours.get("hooks").and_then(Value::as_object) else {
        return false;
    };
    ours.iter().all(|(event, entries)| {
        let held = theirs.get(event).unwrap_or(&Value::Null);
        entries.as_array().into_iter().flatten().all(|e| {
            e["hooks"]
                .as_array()
                .into_iter()
                .flatten()
                .all(|h| holds_handler(held, &e["matcher"], h))
        })
    })
}

/// One registry read as [`hklm_policy`] wants it: only "not found" means
/// absent. Every other error (access denied, a REG_DWORD or REG_BINARY
/// value where a string is expected, ...) is `Err`.
pub fn hklm_read(r: std::io::Result<String>) -> HklmRead {
    match r {
        Ok(t) => Ok(Some(t)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(HklmReadError),
    }
}

/// [`hklm_policy`] against the real registry (64-bit view of HKLM).
#[cfg(windows)]
pub fn hklm_policy_live() -> HklmPolicy {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};
    use winreg::RegKey;
    hklm_policy(&|key, value| {
        match RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey_with_flags(key, KEY_READ | KEY_WOW64_64KEY)
        {
            // A missing key is as absent as a missing value.
            Err(e) => hklm_read(Err(e)),
            Ok(k) => hklm_read(k.get_value::<String, _>(value)),
        }
    })
}

/// The managed drop-in `60-saiife-mcp.json`: Claude Code may start only
/// what it names. The broker's own server is pinned by command, so a
/// project `.mcp.json` cannot define its own `saiife` server; the admin's
/// `allow_servers` (gateway servers) follow by name, in order, without
/// repeats. `saiife` is never allowed by name.
pub fn managed_mcp_settings(allow_servers: &[String]) -> String {
    managed_mcp_settings_for(cfg!(windows), allow_servers)
}

/// [`managed_mcp_settings`] for a platform. On Windows the pinned command
/// is the W9 binary and no gateway names follow: W18 refuses the gateway
/// there, so `allow_servers` is ignored.
pub fn managed_mcp_settings_for(windows: bool, allow_servers: &[String]) -> String {
    let bin = if windows {
        crate::WINDOWS_BINARY
    } else {
        SAIIFE_BINARY
    };
    let mut entries: Vec<Value> = vec![json!({ "serverCommand": [bin, "mcp"] })];
    let mut seen: Vec<&str> = Vec::new();
    for s in allow_servers.iter().filter(|_| !windows) {
        if s != "saiife" && !seen.contains(&s.as_str()) {
            seen.push(s);
            entries.push(json!({ "serverName": s }));
        }
    }
    let mut text =
        serde_json::to_string_pretty(&json!({ "allowedMcpServers": entries })).unwrap_or_default();
    text.push('\n');
    text
}

/// Whether `text` is a drop-in [`managed_mcp_settings`] would write: the
/// pinned `saiife` command first, then `serverName` entries only, none of
/// them `saiife`, nothing else. Anything more (another `serverCommand`, a
/// `serverUrl`, a `saiife` by name, another key) could let a server that
/// is not saiife's own run under the name `saiife`.
pub fn managed_mcp_pinned(text: &str) -> bool {
    managed_mcp_pinned_for(cfg!(windows), text)
}

/// [`managed_mcp_pinned`] for a platform (on Windows: the pin alone).
pub fn managed_mcp_pinned_for(windows: bool, text: &str) -> bool {
    let Ok(v) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    let Some(entries) = v.get("allowedMcpServers").and_then(Value::as_array) else {
        return false;
    };
    let names: Vec<String> = entries
        .iter()
        .filter_map(|e| e.get("serverName")?.as_str().map(str::to_string))
        .collect();
    serde_json::from_str::<Value>(&managed_mcp_settings_for(windows, &names))
        .is_ok_and(|want| want == v)
}

/// The installed binary (the same path the hook command uses).
const SAIIFE_BINARY: &str = "/opt/saiife/bin/saiife";

fn group() -> Value {
    json!({
        "matcher": MATCHER,
        "hooks": [{
            "type": "command",
            "command": Agent::Claude.hook_command(),
            "timeout": TIMEOUT_SECS,
        }]
    })
}

const HOOKS: JsonHooks = JsonHooks {
    rel: SETTINGS_REL,
    event: "PreToolUse",
    group,
};

pub fn install(project: &Path) -> Result<Change, AgentError> {
    HOOKS.install(project)
}

pub fn remove(project: &Path, delete_if_empty: bool) -> Result<Change, AgentError> {
    HOOKS.remove(project, delete_if_empty)
}

pub fn entries(project: &Path) -> Result<Vec<String>, AgentError> {
    HOOKS.entries(project)
}

/// The matcher of saiife's group in the project's settings (the first), or
/// `None` when the file is missing, unreadable, not plain JSON, or has no
/// saiife hook. `status` uses it to tell an out-of-date matcher from other
/// changes.
pub fn project_matcher(project: &Path) -> Option<String> {
    let text = std::fs::read_to_string(project.join(SETTINGS_REL)).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    v.get("hooks")?
        .get("PreToolUse")?
        .as_array()?
        .iter()
        .find(|g| {
            g.get("hooks").and_then(Value::as_array).is_some_and(|hs| {
                hs.iter().any(|h| {
                    h.get("command")
                        .and_then(Value::as_str)
                        .is_some_and(crate::is_saiife_command)
                })
            })
        })?
        .get("matcher")?
        .as_str()
        .map(str::to_string)
}

pub fn expected_entry() -> String {
    HOOKS.expected()
}

/// Settings that stop the project hook from running: `disableAllHooks: true`
/// in project, local or user settings, and `allowManagedHooksOnly` /
/// `disableAllHooks` in managed settings.
pub fn blockers(project: &Path, home: Option<&Path>) -> Vec<HookBlocker> {
    blockers_in(project, home, &managed_dirs())
}

/// The managed-settings directories. Debug builds (tests) can replace them
/// with `SAIIFE_TEST_CLAUDE_MANAGED_DIRS` (a PATH-style list); a release
/// build ignores it, so it cannot be used to hide a managed lock.
fn managed_dirs() -> Vec<PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(v) = std::env::var_os("SAIIFE_TEST_CLAUDE_MANAGED_DIRS") {
        return std::env::split_paths(&v).collect();
    }
    MANAGED_DIRS.iter().map(PathBuf::from).collect()
}

/// `blockers` with the managed-settings directories given (tests).
pub fn blockers_in(
    project: &Path,
    home: Option<&Path>,
    managed_dirs: &[PathBuf],
) -> Vec<HookBlocker> {
    let mut files = vec![
        project.join(".claude/settings.json"),
        project.join(".claude/settings.local.json"),
    ];
    if let Some(home) = home {
        files.push(home.join(".claude/settings.json"));
    }
    let mut out = Vec::new();
    for f in &files {
        check_flag(&mut out, f, "disableAllHooks", false);
    }
    for dir in managed_dirs {
        let mut managed = vec![dir.join("managed-settings.json")];
        let d = dir.join("managed-settings.d");
        match std::fs::read_dir(&d) {
            Ok(rd) => {
                let mut dropins: Vec<PathBuf> = Vec::new();
                for e in rd {
                    match e {
                        Ok(e) => dropins.push(e.path()),
                        Err(err) => out.push(unreadable(&d, &err, true)),
                    }
                }
                dropins.retain(|p| p.extension().is_some_and(|x| x == "json"));
                dropins.sort();
                managed.extend(dropins);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => out.push(unreadable(&d, &e, true)),
        }
        for f in managed {
            // Read once; report an unreadable file once, not per setting.
            // A managed file that is not a JSON object cannot be read as
            // settings: report it like an unreadable one.
            match read_flags(&f) {
                Ok(v) if !v.is_object() && !(v.is_null() && !f.exists()) => {
                    out.push(unreadable_msg(&f, "not a JSON object".into(), true))
                }
                Ok(v) => {
                    for setting in ["allowManagedHooksOnly", "disableAllHooks"] {
                        if v.get(setting).and_then(Value::as_bool) == Some(true) {
                            out.push(HookBlocker {
                                path: f.clone(),
                                setting,
                                error: None,
                                managed: true,
                            });
                        }
                    }
                }
                Err(e) => out.push(unreadable_msg(&f, e, true)),
            }
        }
    }
    out
}

fn unreadable_msg(path: &Path, error: String, managed: bool) -> HookBlocker {
    HookBlocker {
        path: path.to_path_buf(),
        setting: "",
        error: Some(error),
        managed,
    }
}

fn unreadable(path: &Path, e: &std::io::Error, managed: bool) -> HookBlocker {
    unreadable_msg(path, e.to_string(), managed)
}

/// The JSON of `path`; an absent file is an empty object, an unreadable or
/// unparseable one is an error.
fn read_flags(path: &Path) -> Result<Value, String> {
    match std::fs::read_to_string(path) {
        Ok(t) => serde_json::from_str::<Value>(&t).map_err(|e| format!("not valid JSON: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Value::Null),
        Err(e) => Err(e.to_string()),
    }
}

fn check_flag(out: &mut Vec<HookBlocker>, path: &Path, key: &'static str, managed: bool) {
    match read_flags(path) {
        Ok(v) if v.get(key).and_then(Value::as_bool) == Some(true) => out.push(HookBlocker {
            path: path.to_path_buf(),
            setting: key,
            error: None,
            managed,
        }),
        Ok(_) => {}
        Err(e) => out.push(unreadable_msg(path, e, managed)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A user settings file with unrelated keys, a user hook in the same
    /// event, and another event — all must survive init and init --off.
    const USER_SETTINGS: &str = r#"{
  "model": "opus",
  "permissions": {
    "allow": [
      "Bash(npm run test:*)"
    ],
    "deny": []
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "./scripts/lint-hook.sh"
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "notify-send done"
          }
        ]
      }
    ]
  },
  "env": {
    "FOO": "bar"
  }
}
"#;

    fn project_with(settings: &str) -> tempfile::TempDir {
        let p = tempfile::tempdir().unwrap();
        fs::create_dir(p.path().join(".claude")).unwrap();
        fs::write(p.path().join(SETTINGS_REL), settings).unwrap();
        p
    }

    fn read(p: &Path) -> String {
        fs::read_to_string(p.join(SETTINGS_REL)).unwrap()
    }

    #[test]
    fn install_adds_the_hook_and_keeps_user_settings() {
        let p = project_with(USER_SETTINGS);
        assert_eq!(install(p.path()).unwrap(), Change::Updated);
        let v: Value = serde_json::from_str(&read(p.path())).unwrap();
        let groups = v["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(groups.len(), 2, "user group kept, saiife group added");
        assert_eq!(groups[0]["hooks"][0]["command"], "./scripts/lint-hook.sh");
        assert_eq!(groups[1]["matcher"], MATCHER);
        assert_eq!(
            groups[1]["hooks"][0]["command"],
            "saiife check --hook-exit --agent claude"
        );
        assert_eq!(groups[1]["hooks"][0]["timeout"], 10);
        assert!(groups[1]["hooks"][0].get("onFailure").is_none());
        assert_eq!(v["model"], "opus");
        assert_eq!(v["env"]["FOO"], "bar");
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            ["model", "permissions", "hooks", "env"],
            "key order kept"
        );
        assert_eq!(entries(p.path()).unwrap(), vec![expected_entry()]);
    }

    #[test]
    fn second_install_is_a_no_op() {
        let p = project_with(USER_SETTINGS);
        install(p.path()).unwrap();
        let once = read(p.path());
        assert_eq!(install(p.path()).unwrap(), Change::Unchanged);
        assert_eq!(read(p.path()), once);
    }

    #[test]
    fn remove_restores_the_original_bytes() {
        let p = project_with(USER_SETTINGS);
        install(p.path()).unwrap();
        assert_eq!(remove(p.path(), false).unwrap(), Change::Updated);
        assert_eq!(read(p.path()), USER_SETTINGS);
        assert_eq!(remove(p.path(), false).unwrap(), Change::Unchanged);
    }

    #[test]
    fn four_space_indent_round_trips() {
        let four = "{\n    \"model\": \"opus\"\n}\n";
        let p = project_with(four);
        install(p.path()).unwrap();
        assert!(read(p.path()).contains("\n        \"PreToolUse\""));
        remove(p.path(), false).unwrap();
        assert_eq!(read(p.path()), four);
    }

    /// F2: a CRLF file stays CRLF, and init then --off restores its bytes.
    #[test]
    fn crlf_settings_round_trip() {
        let crlf = USER_SETTINGS.replace('\n', "\r\n");
        let p = project_with(&crlf);
        install(p.path()).unwrap();
        let installed = read(p.path());
        assert!(installed.contains("saiife check"));
        assert_eq!(
            installed.matches('\n').count(),
            installed.matches("\r\n").count(),
            "every line ends in CRLF: {installed:?}"
        );
        assert_eq!(entries(p.path()).unwrap(), vec![expected_entry()]);
        assert_eq!(remove(p.path(), false).unwrap(), Change::Updated);
        assert_eq!(read(p.path()), crlf);
    }

    #[test]
    fn creates_the_file_and_deletes_it_again() {
        let p = tempfile::tempdir().unwrap();
        assert_eq!(
            install(p.path()).unwrap(),
            Change::Created {
                created_dirs: vec![".claude".into()]
            }
        );
        assert_eq!(remove(p.path(), true).unwrap(), Change::Deleted);
        assert!(!p.path().join(SETTINGS_REL).exists());
    }

    fn reg(v: Option<&'static str>) -> impl Fn(&str, &str) -> HklmRead {
        move |k, n| {
            assert_eq!((k, n), (HKLM_POLICY_KEY, HKLM_POLICY_VALUE));
            Ok(v.map(str::to_string))
        }
    }

    /// Any read error except "not found" fails closed.
    #[test]
    fn hklm_read_errors_fail_closed() {
        let failing = |_: &str, _: &str| Err(HklmReadError);
        assert_eq!(hklm_policy(&failing), HklmPolicy::Overrides);
    }

    #[test]
    fn hklm_only_not_found_is_absent() {
        use std::io::{Error, ErrorKind};
        assert_eq!(hklm_read(Err(Error::from(ErrorKind::NotFound))), Ok(None));
        assert_eq!(hklm_read(Ok("{}".into())), Ok(Some("{}".to_string())));
        for k in [
            ErrorKind::PermissionDenied,
            ErrorKind::InvalidData, // a REG_DWORD or REG_BINARY value
            ErrorKind::Other,
            ErrorKind::InvalidInput,
        ] {
            assert_eq!(hklm_read(Err(Error::from(k))), Err(HklmReadError), "{k:?}");
        }
    }

    #[test]
    fn windows_mcp_dropin_pins_the_windows_binary() {
        let w = managed_mcp_settings_for(true, &["github".into()]);
        let v: Value = serde_json::from_str(&w).unwrap();
        assert_eq!(
            v,
            json!({"allowedMcpServers": [
                {"serverCommand": ["C:/ProgramData/saiife/bin/saiife.exe", "mcp"]}
            ]})
        );
        assert!(managed_mcp_pinned_for(true, &w));
        assert!(!managed_mcp_pinned_for(false, &w));
        assert!(!w.contains("/opt/"));
        // A gateway name on Windows is not what install writes.
        let with_name = serde_json::to_string(&json!({"allowedMcpServers": [
            {"serverCommand": ["C:/ProgramData/saiife/bin/saiife.exe", "mcp"]},
            {"serverName": "github"}]}))
        .unwrap();
        assert!(!managed_mcp_pinned_for(true, &with_name));
    }

    #[test]
    fn linux_mcp_dropin_unchanged() {
        let a = managed_mcp_settings_for(false, &["x".into(), "saiife".into(), "x".into()]);
        assert_eq!(
            a,
            "{\n  \"allowedMcpServers\": [\n    {\n      \"serverCommand\": [\n        \"/opt/saiife/bin/saiife\",\n        \"mcp\"\n      ]\n    },\n    {\n      \"serverName\": \"x\"\n    }\n  ]\n}\n"
        );
        assert!(managed_mcp_pinned_for(false, &a));
        assert!(!managed_mcp_pinned_for(true, &a));
    }

    #[test]
    fn hklm_settings_without_merge_fails() {
        let r = reg(Some(r#"{"permissions":{"deny":["x"]}}"#));
        assert_eq!(hklm_policy(&r), HklmPolicy::Overrides);
        let r = reg(Some(r#"{"hooks":{},"managedSourcesBehavior":"replace"}"#));
        assert_eq!(hklm_policy(&r), HklmPolicy::Overrides);
        assert_eq!(hklm_policy(&reg(Some("not json"))), HklmPolicy::Overrides);
    }

    #[test]
    fn hklm_merge_with_hooks_off_weakens() {
        let read = |text: String| hklm_policy(&move |_, _| Ok(Some(text.clone())));
        let m = |rest: &str| format!(r#"{{"managedSourcesBehavior":"merge"{rest}}}"#);
        assert_eq!(
            read(m(r#","disableAllHooks":true"#)),
            HklmPolicy::WeakensHooks
        );
        assert_eq!(read(m(r#","disableAllHooks":1"#)), HklmPolicy::WeakensHooks);
        assert_eq!(read(m(r#","disableAllHooks":false"#)), HklmPolicy::Merge);
        assert_eq!(read(m(r#","hooks":{}"#)), HklmPolicy::WeakensHooks);
        let ours: Value = serde_json::from_str(&managed_settings_for(true)).unwrap();
        let hooks = format!(
            r#","hooks":{},"allowedHttpHookUrls":["{COSIGN_URL_PATTERN}"]"#,
            ours["hooks"]
        );
        assert_eq!(read(m(&hooks)), HklmPolicy::Merge);
        // Without merge the source replaces the files, whatever else it says.
        assert_eq!(
            read(r#"{"disableAllHooks":true}"#.to_string()),
            HklmPolicy::Overrides
        );
    }

    /// A merged policy whose `hooks` keeps saiife's commands but not its whole handlers
    /// (plan 20, the Task 5 security review): each of these can let a killed hook pass.
    #[test]
    fn hklm_hooks_without_the_whole_handlers_weaken() {
        let ours: Value = serde_json::from_str(&managed_settings_for(true)).unwrap();
        let read = |hooks: &Value, listed: bool| {
            let mut p = json!({"managedSourcesBehavior": "merge", "hooks": hooks});
            if listed {
                p["allowedHttpHookUrls"] = json!([COSIGN_URL_PATTERN]);
            }
            let text = p.to_string();
            hklm_policy(&move |_, _| Ok(Some(text.clone())))
        };
        assert_eq!(read(&ours["hooks"], true), HklmPolicy::Merge);
        // The same handlers in another order, and an admin hook beside them, still carry.
        let mut more = ours["hooks"].clone();
        more["PreToolUse"][0]["hooks"]
            .as_array_mut()
            .unwrap()
            .reverse();
        more["PreToolUse"]
            .as_array_mut()
            .unwrap()
            .push(json!({"matcher": "Bash", "hooks": [{"type": "command", "command": "x"}]}));
        assert_eq!(read(&more, true), HklmPolicy::Merge);
        // The commands, without the co-signer's HTTP handler.
        let mut no_http = ours["hooks"].clone();
        no_http["PreToolUse"][0]["hooks"]
            .as_array_mut()
            .unwrap()
            .retain(|h| h["type"] != "http");
        assert_eq!(read(&no_http, true), HklmPolicy::WeakensHooks);
        // The HTTP handler at another URL.
        let mut moved = ours["hooks"].clone();
        moved["PreToolUse"][0]["hooks"][1]["url"] = json!("http://127.0.0.1:9/x");
        assert_eq!(read(&moved, true), HklmPolicy::WeakensHooks);
        // A handler whose failure no longer blocks.
        for i in 0..2 {
            let mut open = ours["hooks"].clone();
            open["PreToolUse"][0]["hooks"][i]
                .as_object_mut()
                .unwrap()
                .remove("onFailure");
            assert_eq!(read(&open, true), HklmPolicy::WeakensHooks, "{i}");
        }
        let mut open = ours["hooks"].clone();
        open["ConfigChange"][0]["hooks"][0]["onFailure"] = json!("allow");
        assert_eq!(read(&open, true), HklmPolicy::WeakensHooks);
        // A narrower matcher.
        let mut narrow = ours["hooks"].clone();
        narrow["PreToolUse"][0]["matcher"] = json!("Bash");
        assert_eq!(read(&narrow, true), HklmPolicy::WeakensHooks);
        // The handlers without the allow-list entry.
        assert_eq!(read(&ours["hooks"], false), HklmPolicy::WeakensHooks);
    }

    #[test]
    fn hklm_merge_passes() {
        let r = reg(Some(
            r#"{"env":{"A":"1"},"managedSourcesBehavior":"merge"}"#,
        ));
        assert_eq!(hklm_policy(&r), HklmPolicy::Merge);
    }

    #[test]
    fn hklm_absent() {
        assert_eq!(hklm_policy(&reg(None)), HklmPolicy::Absent);
        assert_eq!(hklm_policy(&reg(Some(""))), HklmPolicy::Absent);
    }

    #[test]
    fn hklm_only_control_keys_is_absent() {
        let r = reg(Some(
            r#"{"managedSourcesBehavior":"merge","wslInheritsWindowsSettings":true}"#,
        ));
        assert_eq!(hklm_policy(&r), HklmPolicy::Absent);
        assert_eq!(hklm_policy(&reg(Some("{}"))), HklmPolicy::Absent);
    }

    #[test]
    fn hklm_text_is_the_spec_line() {
        assert_eq!(
            HKLM_OVERRIDES_TEXT,
            "HKLM\\SOFTWARE\\Policies\\ClaudeCode sets Claude Code's managed settings, so saiife's drop-in is ignored; add \"managedSourcesBehavior\": \"merge\" there, or put saiife's hooks in it"
        );
    }

    /// Linux output is the pinned bytes; Windows differs in the command only.
    #[test]
    fn windows_claude_dropin_golden() {
        assert_eq!(managed_settings_for(false), MANAGED_SETTINGS);
        let w = managed_settings_for(true);
        assert_eq!(
            w.matches(
                "C:/ProgramData/saiife/bin/saiife.exe check --managed --hook-exit --agent claude"
            )
            .count(),
            2
        );
        assert_eq!(
            w.replace(crate::WINDOWS_BINARY, crate::UNIX_BINARY),
            MANAGED_SETTINGS
        );
        assert!(!w.contains("/opt/"));
        let v: Value = serde_json::from_str(&w).unwrap();
        assert_eq!(v["disableAllHooks"], false);
        assert_eq!(
            v["hooks"]["PreToolUse"][0]["hooks"][0]["onFailure"],
            "block"
        );
    }

    /// The drop-in of plan 20 Task 5, byte for byte (spec §8.3).
    #[test]
    fn managed_settings_bytes() {
        const WANT: &str = r#"{
  "hooks": {
    "PreToolUse": [
      { "matcher": "*",
        "hooks": [ { "type": "command",
                     "command": "/opt/saiife/bin/saiife check --managed --hook-exit --agent claude",
                     "timeout": 10, "onFailure": "block" },
                   { "type": "http",
                     "url": "http://127.0.0.1:7433/v1/cosign/claude",
                     "timeout": 10, "onFailure": "block" } ] }
    ],
    "ConfigChange": [
      { "hooks": [ { "type": "command",
                     "command": "/opt/saiife/bin/saiife check --managed --hook-exit --agent claude --event config-change",
                     "timeout": 10, "onFailure": "block" } ] }
    ]
  },
  "allowedHttpHookUrls": ["http://127.0.0.1:7433/*"],
  "disableAllHooks": false
}
"#;
        assert_eq!(managed_settings_for(false), WANT);
        assert_eq!(MANAGED_SETTINGS, WANT);
        assert!(carries_cosign(WANT));
    }

    /// The co-signer's URL holds no binary path, so Windows keeps it as is.
    #[test]
    fn windows_differs_in_the_command_only() {
        let (l, w) = (managed_settings_for(false), managed_settings_for(true));
        let differ: Vec<(&str, &str)> = l.lines().zip(w.lines()).filter(|(a, b)| a != b).collect();
        assert_eq!(l.lines().count(), w.lines().count());
        assert_eq!(differ.len(), 2, "{differ:?}");
        assert!(differ.iter().all(|(a, _)| a.contains("\"command\"")));
        let v: Value = serde_json::from_str(&w).unwrap();
        let http = &v["hooks"]["PreToolUse"][0]["hooks"][1];
        assert_eq!(http["url"], COSIGN_URL);
        assert_eq!(v["allowedHttpHookUrls"], json!([COSIGN_URL_PATTERN]));
        assert!(carries_cosign(&w));
    }

    /// saiife sends no headers, so `httpHookAllowedEnvVars` cannot touch it.
    #[test]
    fn http_hook_has_no_headers() {
        for windows in [false, true] {
            let v: Value = serde_json::from_str(&managed_settings_for(windows)).unwrap();
            let http = v["hooks"]["PreToolUse"][0]["hooks"][1].as_object().unwrap();
            let keys: Vec<&str> = http.keys().map(String::as_str).collect();
            assert_eq!(keys, ["type", "url", "timeout", "onFailure"]);
            assert_eq!(http["type"], "http");
            assert_eq!(http["timeout"], 10);
            assert_eq!(http["onFailure"], "block");
            assert!(!managed_settings_for(windows).contains("headers"));
            assert!(!managed_settings_for(windows).contains("allowedEnvVars"));
        }
    }

    /// `*` matches any run of characters, as Claude Code's allow-list reads it.
    fn glob(pattern: &str, s: &str) -> bool {
        match pattern.split_once('*') {
            None => pattern == s,
            Some((head, rest)) => {
                let Some(tail) = s.strip_prefix(head) else {
                    return false;
                };
                (0..=tail.len())
                    .filter(|&i| tail.is_char_boundary(i))
                    .any(|i| glob(rest, &tail[i..]))
            }
        }
    }

    #[test]
    fn allow_list_admits_the_url() {
        assert!(glob(COSIGN_URL_PATTERN, COSIGN_URL));
        assert!(!glob(
            COSIGN_URL_PATTERN,
            "http://127.0.0.1:7434/v1/cosign/claude"
        ));
        assert!(!glob(
            COSIGN_URL_PATTERN,
            "http://localhost:7433/v1/cosign/claude"
        ));
        assert_eq!(COSIGN_URL, "http://127.0.0.1:7433/v1/cosign/claude");
        assert_eq!(COSIGN_URL_PATTERN, "http://127.0.0.1:7433/*");
    }

    /// What doctor's `agents.claude.policy` asks of an installed drop-in.
    #[test]
    fn a_drop_in_without_the_cosigner_is_not_enough() {
        let old = r#"{
  "hooks": {
    "PreToolUse": [
      { "matcher": "*",
        "hooks": [ { "type": "command",
                     "command": "/opt/saiife/bin/saiife check --managed --hook-exit --agent claude",
                     "timeout": 10, "onFailure": "block" } ] }
    ]
  },
  "disableAllHooks": false
}
"#;
        assert!(!carries_cosign(old));
        let ours = managed_settings();
        assert!(carries_cosign(ours));
        let no_list = ours.replace(
            "\n  \"allowedHttpHookUrls\": [\"http://127.0.0.1:7433/*\"],",
            "",
        );
        assert_ne!(no_list, ours);
        assert!(!carries_cosign(&no_list));
        let fails_open = ours.replacen(
            "\"url\": \"http://127.0.0.1:7433/v1/cosign/claude\",\n                     \"timeout\": 10, \"onFailure\": \"block\"",
            "\"url\": \"http://127.0.0.1:7433/v1/cosign/claude\",\n                     \"timeout\": 10",
            1,
        );
        assert_ne!(fails_open, ours);
        assert!(!carries_cosign(&fails_open));
        assert!(!carries_cosign(
            &ours.replace(COSIGN_URL, "http://127.0.0.1:9/x")
        ));
        assert!(!carries_cosign("not json"));
        assert!(!carries_cosign("{}"));
    }

    /// `status` reads Claude's managed file on Windows too.
    #[test]
    fn windows_managed_dir_is_pinned() {
        assert_eq!(WINDOWS_MANAGED_DIR, "C:\\Program Files\\ClaudeCode");
        #[cfg(windows)]
        assert_eq!(MANAGED_DIRS, [WINDOWS_MANAGED_DIR]);
    }

    #[test]
    fn matcher_covers_powershell() {
        assert!(MATCHER.split('|').any(|t| t == "PowerShell"));
        assert!(!MATCHER_V2.contains("PowerShell"));
        assert!(!MATCHER_V1.contains("PowerShell"));
        assert!(matcher_is_outdated(MATCHER_V1));
        assert!(matcher_is_outdated(MATCHER_V2));
        assert!(!matcher_is_outdated(MATCHER));
        assert_eq!(MATCHER.replace("PowerShell|", ""), MATCHER_V2);
    }

    /// A project hooked by the pre-PowerShell matcher gets the new one; the
    /// user's other groups and the key order are untouched.
    #[test]
    fn matcher_v2_project_upgraded() {
        let p = project_with(USER_SETTINGS);
        install(p.path()).unwrap();
        let fresh = read(p.path());
        let old = fresh.replace(MATCHER, MATCHER_V2);
        assert_ne!(old, fresh);
        fs::write(p.path().join(SETTINGS_REL), &old).unwrap();
        assert_ne!(entries(p.path()).unwrap(), vec![expected_entry()]);
        assert_eq!(install(p.path()).unwrap(), Change::Updated);
        assert_eq!(entries(p.path()).unwrap(), vec![expected_entry()]);
        // Byte for byte what a fresh install wrote: the user's groups and
        // the key order are as they were.
        assert_eq!(read(p.path()), fresh);
    }

    #[test]
    fn matcher_covers_read_list_and_write_tools() {
        let tools: Vec<&str> = MATCHER.split('|').collect();
        for t in [
            "Bash",
            "PowerShell",
            "Read",
            "Grep",
            "Glob",
            "LS",
            "Write",
            "Edit",
            "MultiEdit",
            "NotebookEdit",
        ] {
            assert!(tools.contains(&t), "{t}");
        }
    }

    /// The fingerprint `status` compares against the recorded one. Pinned so
    /// a change of the entry is a deliberate act (and an upgrade for users).
    #[test]
    fn expected_entry_fingerprint_is_pinned() {
        assert_eq!(
            expected_entry(),
            "79bee8986b3cf00133dd2f437b9980d6b199d60e1b1b048a1447165145d758f4"
        );
    }

    /// An install from plan 2 (old matcher) is upgraded in place.
    #[test]
    fn an_older_entry_is_upgraded_by_install() {
        let p = project_with(USER_SETTINGS);
        install(p.path()).unwrap();
        let old = read(p.path()).replace(MATCHER, MATCHER_V1);
        fs::write(p.path().join(SETTINGS_REL), &old).unwrap();
        assert_eq!(
            entries(p.path()).unwrap(),
            vec!["78ff3176c0d50b70275b537d4f8e7c52ebba6e0ce22f68c03d01d52fd86c5d76".to_string()]
        );
        assert_ne!(entries(p.path()).unwrap(), vec![expected_entry()]);
        assert_eq!(install(p.path()).unwrap(), Change::Updated);
        assert_eq!(entries(p.path()).unwrap(), vec![expected_entry()]);
        assert!(read(p.path()).contains(MATCHER));
    }

    #[test]
    fn a_changed_entry_is_replaced_not_duplicated() {
        let p = project_with(USER_SETTINGS);
        install(p.path()).unwrap();
        let tampered = read(p.path()).replace(MATCHER, "NeverMatches");
        fs::write(p.path().join(SETTINGS_REL), tampered).unwrap();
        assert_eq!(entries(p.path()).unwrap().len(), 1);
        assert_ne!(entries(p.path()).unwrap(), vec![expected_entry()]);
        assert_eq!(install(p.path()).unwrap(), Change::Updated);
        assert_eq!(entries(p.path()).unwrap(), vec![expected_entry()]);
    }

    /// Review Focus 2: a settings file that is not plain JSON is never
    /// rewritten.
    #[test]
    fn unparseable_settings_are_left_byte_identical() {
        for bad in [
            "{\n  // my comment\n  \"model\": \"opus\"\n}\n",
            "{\"model\": \"opus\",}\n",
            "[1, 2]\n",
            "{\"hooks\": {\"PreToolUse\": {\"matcher\": \"Bash\"}}}\n",
            "{\"hooks\": []}\n",
            "{\"hooks\": \"x\"}\n",
        ] {
            let p = project_with(bad);
            assert!(install(p.path()).is_err(), "{bad:?}");
            assert!(
                remove(p.path(), true).is_err() || read(p.path()) == bad,
                "{bad:?}"
            );
            assert_eq!(read(p.path()), bad, "{bad:?}");
        }
    }

    #[test]
    fn blockers_find_disable_all_hooks_and_managed_settings() {
        let p = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let managed = tempfile::tempdir().unwrap();
        assert!(
            blockers_in(p.path(), Some(home.path()), &[managed.path().to_path_buf()]).is_empty()
        );

        fs::create_dir(p.path().join(".claude")).unwrap();
        fs::write(
            p.path().join(".claude/settings.local.json"),
            r#"{"disableAllHooks": true}"#,
        )
        .unwrap();
        fs::create_dir(home.path().join(".claude")).unwrap();
        fs::write(
            home.path().join(".claude/settings.json"),
            r#"{"disableAllHooks": false}"#,
        )
        .unwrap();
        fs::create_dir(managed.path().join("managed-settings.d")).unwrap();
        fs::write(
            managed.path().join("managed-settings.d/10-lock.json"),
            r#"{"allowManagedHooksOnly": true}"#,
        )
        .unwrap();
        let found = blockers_in(p.path(), Some(home.path()), &[managed.path().to_path_buf()]);
        let settings: Vec<&str> = found.iter().map(|b| b.setting).collect();
        assert_eq!(settings, ["disableAllHooks", "allowManagedHooksOnly"]);
        assert!(found[0].path.ends_with(".claude/settings.local.json"));
        assert!(found[1].managed && found[1].error.is_none());
    }

    /// M5: a managed drop-in whose JSON is not an object is reported like an
    /// unreadable file, not silently skipped.
    #[test]
    fn non_object_managed_drop_in_is_reported() {
        let p = tempfile::tempdir().unwrap();
        let managed = tempfile::tempdir().unwrap();
        fs::create_dir(managed.path().join("managed-settings.d")).unwrap();
        for (name, body) in [("a.json", "[1]"), ("b.json", "null"), ("c.json", "\"x\"")] {
            fs::write(managed.path().join("managed-settings.d").join(name), body).unwrap();
        }
        let found = blockers_in(p.path(), None, &[managed.path().to_path_buf()]);
        assert_eq!(found.len(), 3, "{found:?}");
        assert!(found
            .iter()
            .all(|b| b.managed && b.setting.is_empty() && b.error.is_some()));
        assert!(found[0]
            .error
            .as_deref()
            .unwrap()
            .contains("not a JSON object"));
    }

    #[test]
    fn unparseable_or_unreadable_inputs_are_reported_not_ignored() {
        let p = project_with("{ not json");
        let home = tempfile::tempdir().unwrap();
        let managed = tempfile::tempdir().unwrap();
        // A directory where managed-settings.json should be: unreadable even
        // as root.
        fs::create_dir(managed.path().join("managed-settings.json")).unwrap();
        fs::create_dir(managed.path().join("managed-settings.d")).unwrap();
        fs::write(managed.path().join("managed-settings.d/a.json"), "][").unwrap();
        let found = blockers_in(p.path(), Some(home.path()), &[managed.path().to_path_buf()]);
        let errs: Vec<&HookBlocker> = found.iter().filter(|b| b.error.is_some()).collect();
        assert_eq!(errs.len(), 3, "{found:?}");
        assert!(errs[0].path.ends_with(".claude/settings.json"));
        assert!(errs[1].managed && errs[2].managed);
        assert!(found.iter().all(|b| b.setting.is_empty()));
    }
}

#[cfg(test)]
mod mcp_tests {
    use super::*;

    #[test]
    fn managed_mcp_pinned_only_for_saiifes_own_text() {
        let good = managed_mcp_settings(&["linear".to_string(), "docs".to_string()]);
        assert!(managed_mcp_pinned(&good));
        assert!(managed_mcp_pinned(&managed_mcp_settings(&[])));
        for bad in [
            "",
            "{}",
            "not json",
            r#"{"allowedMcpServers": []}"#,
            r#"{"allowedMcpServers": [{"serverCommand": ["/opt/saiife/bin/saiife", "mcp", "--wait", "5m"]}]}"#,
            r#"{"allowedMcpServers": [{"serverCommand": ["/tmp/saiife", "mcp"]}]}"#,
            r#"{"allowedMcpServers": [{"serverCommand": ["/opt/saiife/bin/saiife", "mcp"]}, {"serverName": "saiife"}]}"#,
            r#"{"allowedMcpServers": [{"serverCommand": ["/opt/saiife/bin/saiife", "mcp"]}, {"serverCommand": ["/usr/bin/x"]}]}"#,
            r#"{"allowedMcpServers": [{"serverCommand": ["/opt/saiife/bin/saiife", "mcp"]}], "x": 1}"#,
        ] {
            assert!(!managed_mcp_pinned(bad), "{bad}");
        }
    }

    #[test]
    fn managed_mcp_settings_pins_saiife_by_command() {
        let servers = [
            "github".to_string(),
            "saiife".to_string(),
            "jira".to_string(),
            "github".to_string(),
        ];
        // What production calls follows the host.
        assert_eq!(
            managed_mcp_settings(&servers),
            managed_mcp_settings_for(cfg!(windows), &servers)
        );
        let text = managed_mcp_settings_for(false, &servers);
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            v,
            json!({"allowedMcpServers": [
                {"serverCommand": ["/opt/saiife/bin/saiife", "mcp"]},
                {"serverName": "github"}, {"serverName": "jira"}
            ]})
        );
        assert!(!text.contains("\"serverName\": \"saiife\""));
    }
}
