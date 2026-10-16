//! Codex: `[[hooks.PreToolUse]]` in `.codex/config.toml`
//! (contract: docs/superpowers/research/2026-10-13-codex-hooks.md).
//!
//! Edited with `toml_edit`, so the user's comments, key order and
//! formatting survive. saiife writes the array-of-tables form
//! (`[[hooks.PreToolUse]]` with `[[hooks.PreToolUse.hooks]]`). A user who
//! wrote the inline form (`PreToolUse = [{ … }]` under `[hooks]`, or
//! `hooks = { PreToolUse = [ … ] }`) keeps it: saiife's group is appended
//! to that array as an inline table, since TOML cannot hold both forms of
//! one key. Any other layout of `hooks.PreToolUse` is reported, never
//! rewritten.

use std::path::{Path, PathBuf};

use serde_json::Value;
use toml_edit::{value, Array, ArrayOfTables, DocumentMut, InlineTable, Item, Table};

use crate::{fingerprint, fsutil, is_saiife_command, Agent, AgentError, Change, HookBlocker};

pub const CONFIG_REL: &str = ".codex/config.toml";

/// Regex on the tool name; `apply_patch` also covers Codex's `Edit`/`Write`
/// aliases.
pub const MATCHER: &str = "^(Bash|apply_patch)$";

/// Seconds.
pub const TIMEOUT_SECS: i64 = 10;

pub const STATUS_MESSAGE: &str = "saiife guard";

pub const NEXT_STEP: &str = "Codex asks you to trust every new or changed hook once: start `codex` in this folder (the project's .codex folder must be trusted), run `/hooks` and trust the saiife hook.";

pub fn install(project: &Path) -> Result<Change, AgentError> {
    fsutil::ensure_inside(project, CONFIG_REL)?;
    let path = project.join(CONFIG_REL);
    let text = fsutil::read_optional(&path)?;
    let mut doc = parse(&path, text.as_deref().unwrap_or(""))?;
    if fingerprints(&path, &doc)? == [expected_entry()] {
        return Ok(Change::Unchanged);
    }
    strip_ours(&path, &mut doc)?;
    match groups_mut(&mut doc) {
        Some(GroupsMut::Tables(groups)) => groups.push(group()),
        Some(GroupsMut::Inline(groups)) => groups.push(inline_group()),
        None => {
            let hooks = doc.entry("hooks").or_insert_with(|| {
                let mut t = Table::new();
                t.set_implicit(true);
                Item::Table(t)
            });
            if let Some(t) = hooks.as_table_mut() {
                let mut groups = ArrayOfTables::new();
                groups.push(group());
                t.insert("PreToolUse", Item::ArrayOfTables(groups));
            } else if let Some(t) = hooks.as_inline_table_mut() {
                t.insert("PreToolUse", Array::from_iter([inline_group()]).into());
            } else {
                return Err(layout(&path, "`hooks` is not a table"));
            }
        }
    }
    let mut out = doc.to_string();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    fsutil::write(project, CONFIG_REL, &out)
}

/// Remove saiife's handlers. With `delete_if_empty`, a file left with no
/// content is deleted (use only for a file saiife created).
pub fn remove(project: &Path, delete_if_empty: bool) -> Result<Change, AgentError> {
    fsutil::ensure_inside(project, CONFIG_REL)?;
    let path = project.join(CONFIG_REL);
    let Some(text) = fsutil::read_optional(&path)? else {
        return Ok(Change::Unchanged);
    };
    let mut doc = parse(&path, &text)?;
    if strip_ours(&path, &mut doc)? == 0 {
        return Ok(Change::Unchanged);
    }
    prune(&mut doc);
    let out = doc.to_string();
    if delete_if_empty && out.trim().is_empty() {
        fsutil::remove(project, CONFIG_REL)?;
        return Ok(Change::Deleted);
    }
    fsutil::write(project, CONFIG_REL, &out)
}

pub fn entries(project: &Path) -> Result<Vec<String>, AgentError> {
    let path = project.join(CONFIG_REL);
    let Some(text) = fsutil::read_optional(&path)? else {
        return Ok(Vec::new());
    };
    fingerprints(&path, &parse(&path, &text)?)
}

pub fn expected_entry() -> String {
    let g = table_to_json(&group());
    entry_fingerprint(g.get("matcher"), &g["hooks"][0])
}

/// `[features] hooks = false` in the project or user config turns every
/// Codex hook off.
pub fn blockers(project: &Path, home: Option<&Path>) -> Vec<HookBlocker> {
    let mut files = vec![project.join(CONFIG_REL)];
    if let Some(home) = home {
        files.push(home.join(".codex/config.toml"));
    }
    let mut out = Vec::new();
    for path in files {
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                out.push(unreadable(path, e.to_string()));
                continue;
            }
        };
        match text.parse::<DocumentMut>() {
            Ok(d) => {
                if d.get("features")
                    .and_then(|f| f.get("hooks"))
                    .and_then(|h| h.as_bool())
                    == Some(false)
                {
                    out.push(HookBlocker {
                        path,
                        setting: "[features] hooks = false",
                        error: None,
                        managed: false,
                    });
                }
            }
            Err(e) => out.push(unreadable(
                path,
                format!(
                    "not valid TOML: {}",
                    e.to_string().trim().replace('\n', " ")
                ),
            )),
        }
    }
    out
}

fn unreadable(path: PathBuf, error: String) -> HookBlocker {
    HookBlocker {
        path,
        setting: "",
        error: Some(error),
        managed: false,
    }
}

/// The `[[hooks.PreToolUse]]` table `install` appends.
fn group() -> Table {
    let mut handler = Table::new();
    handler["type"] = value("command");
    handler["command"] = value(Agent::Codex.hook_command());
    handler["timeout"] = value(TIMEOUT_SECS);
    handler["statusMessage"] = value(STATUS_MESSAGE);
    let mut handlers = ArrayOfTables::new();
    handlers.push(handler);
    let mut g = Table::new();
    g["matcher"] = value(MATCHER);
    g["hooks"] = Item::ArrayOfTables(handlers);
    g
}

/// The same group as an inline table, for a user's inline array.
fn inline_group() -> toml_edit::Value {
    let mut handler = InlineTable::new();
    handler.insert("type", "command".into());
    handler.insert("command", Agent::Codex.hook_command().into());
    handler.insert("timeout", TIMEOUT_SECS.into());
    handler.insert("statusMessage", STATUS_MESSAGE.into());
    let mut g = InlineTable::new();
    g.insert("matcher", MATCHER.into());
    g.insert("hooks", Array::from_iter([handler]).into());
    g.into()
}

fn parse(path: &Path, text: &str) -> Result<DocumentMut, AgentError> {
    text.parse::<DocumentMut>().map_err(|e| AgentError::Parse {
        path: path.to_path_buf(),
        format: "TOML",
        detail: e.to_string().trim().replace('\n', " "),
    })
}

/// `hooks.PreToolUse` in a layout saiife understands.
enum Groups<'a> {
    /// `[[hooks.PreToolUse]]` tables (what saiife writes).
    Tables(&'a ArrayOfTables),
    /// `PreToolUse = [{ … }]`, an inline array of inline tables.
    Inline(&'a Array),
}

enum GroupsMut<'a> {
    Tables(&'a mut ArrayOfTables),
    Inline(&'a mut Array),
}

const BAD_LAYOUT: &str = "`hooks.PreToolUse` is not a list of hook groups ([[hooks.PreToolUse]] tables or an inline array of tables)";

/// `hooks.PreToolUse`, `None` if absent; an error for any other layout.
fn groups<'a>(path: &Path, doc: &'a DocumentMut) -> Result<Option<Groups<'a>>, AgentError> {
    let Some(hooks) = doc.get("hooks") else {
        return Ok(None);
    };
    let Some(pre) = hooks.as_table_like().and_then(|h| h.get("PreToolUse")) else {
        return Ok(None);
    };
    if let Some(t) = pre.as_array_of_tables() {
        return Ok(Some(Groups::Tables(t)));
    }
    match pre.as_array() {
        Some(a) if a.iter().all(toml_edit::Value::is_inline_table) => Ok(Some(Groups::Inline(a))),
        _ => Err(layout(path, BAD_LAYOUT)),
    }
}

/// Mutable `hooks.PreToolUse` (call `groups` first for the layout check).
fn groups_mut(doc: &mut DocumentMut) -> Option<GroupsMut<'_>> {
    let pre = doc
        .get_mut("hooks")?
        .as_table_like_mut()?
        .get_mut("PreToolUse")?;
    if pre.is_array_of_tables() {
        return pre.as_array_of_tables_mut().map(GroupsMut::Tables);
    }
    pre.as_array_mut().map(GroupsMut::Inline)
}

/// Every group as JSON: `{"matcher": …, "hooks": [handler, …]}`.
fn group_values(groups: &Groups) -> Vec<Value> {
    match groups {
        Groups::Tables(t) => t.iter().map(table_to_json).collect(),
        Groups::Inline(a) => a.iter().map(value_to_json).collect(),
    }
}

/// The one test for "this handler is saiife's", on the JSON form.
fn is_ours(handler: &Value) -> bool {
    handler
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(is_saiife_command)
}

/// Indices of saiife's handlers in one group (JSON form).
fn ours_in(group: &Value) -> Vec<usize> {
    group
        .get("hooks")
        .and_then(Value::as_array)
        .map(|hs| {
            hs.iter()
                .enumerate()
                .filter(|(_, h)| is_ours(h))
                .map(|(i, _)| i)
                .collect()
        })
        .unwrap_or_default()
}

fn handler_count(group: &Value) -> usize {
    group
        .get("hooks")
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

fn fingerprints(path: &Path, doc: &DocumentMut) -> Result<Vec<String>, AgentError> {
    let Some(groups) = groups(path, doc)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for g in group_values(&groups) {
        for i in ours_in(&g) {
            out.push(entry_fingerprint(g.get("matcher"), &g["hooks"][i]));
        }
    }
    Ok(out)
}

/// Remove saiife handlers; drop groups left with none. Returns the count.
/// Which handlers are ours is decided once, on the JSON form; only the
/// removal differs per layout.
fn strip_ours(path: &Path, doc: &mut DocumentMut) -> Result<usize, AgentError> {
    let Some(found) = groups(path, doc)? else {
        return Ok(0);
    };
    let plan: Vec<(Vec<usize>, bool)> = group_values(&found)
        .iter()
        .map(|g| {
            let ours = ours_in(g);
            let whole = !ours.is_empty() && ours.len() == handler_count(g);
            (ours, whole)
        })
        .collect();
    let removed = plan.iter().map(|(o, _)| o.len()).sum();
    match groups_mut(doc) {
        None => {}
        Some(GroupsMut::Tables(groups)) => {
            for (gi, (ours, whole)) in plan.iter().enumerate().rev() {
                if *whole {
                    groups.remove(gi);
                } else if let Some(g) = groups.get_mut(gi) {
                    match g.get_mut("hooks") {
                        Some(Item::ArrayOfTables(hs)) => {
                            ours.iter().rev().for_each(|&i| hs.remove(i));
                        }
                        Some(Item::Value(toml_edit::Value::Array(hs))) => {
                            ours.iter().rev().for_each(|&i| {
                                hs.remove(i);
                            });
                        }
                        _ => {}
                    }
                }
            }
        }
        Some(GroupsMut::Inline(groups)) => {
            for (gi, (ours, whole)) in plan.iter().enumerate().rev() {
                if *whole {
                    groups.remove(gi);
                } else if let Some(hs) = groups
                    .get_mut(gi)
                    .and_then(toml_edit::Value::as_inline_table_mut)
                    .and_then(|t| t.get_mut("hooks"))
                    .and_then(toml_edit::Value::as_array_mut)
                {
                    ours.iter().rev().for_each(|&i| {
                        hs.remove(i);
                    });
                }
            }
        }
    }
    Ok(removed)
}

/// Drop `hooks.PreToolUse` and then `hooks` if removing saiife left them
/// empty.
fn prune(doc: &mut DocumentMut) {
    let Some(hooks) = doc.get_mut("hooks").and_then(Item::as_table_like_mut) else {
        return;
    };
    let empty_groups = hooks.get("PreToolUse").is_some_and(|p| {
        p.as_array_of_tables().is_some_and(ArrayOfTables::is_empty)
            || p.as_array().is_some_and(Array::is_empty)
    });
    if empty_groups {
        hooks.remove("PreToolUse");
    }
    if hooks.is_empty() {
        doc.remove("hooks");
    }
}

/// Same scheme as the JSON agents: matcher + handler, as canonical JSON.
/// The same entry fingerprints alike in either layout.
fn entry_fingerprint(matcher: Option<&Value>, handler: &Value) -> String {
    fingerprint::of_json(&serde_json::json!({
        "matcher": matcher.cloned().unwrap_or(Value::Null),
        "handler": handler,
    }))
}

fn table_to_json(t: &Table) -> Value {
    Value::Object(
        t.iter()
            .map(|(k, v)| (k.to_string(), item_to_json(v)))
            .collect(),
    )
}

fn item_to_json(item: &Item) -> Value {
    match item {
        Item::Value(v) => value_to_json(v),
        Item::Table(t) => table_to_json(t),
        Item::ArrayOfTables(a) => Value::Array(a.iter().map(table_to_json).collect()),
        Item::None => Value::Null,
    }
}

fn value_to_json(v: &toml_edit::Value) -> Value {
    use toml_edit::Value as T;
    match v {
        T::String(s) => Value::String(s.value().clone()),
        T::Integer(i) => Value::from(*i.value()),
        T::Float(f) => serde_json::Number::from_f64(*f.value())
            .map(Value::Number)
            .unwrap_or(Value::Null),
        T::Boolean(b) => Value::Bool(*b.value()),
        T::Datetime(d) => Value::String(d.value().to_string()),
        T::Array(a) => Value::Array(a.iter().map(value_to_json).collect()),
        T::InlineTable(t) => Value::Object(
            t.iter()
                .map(|(k, v)| (k.to_string(), value_to_json(v)))
                .collect(),
        ),
    }
}

fn layout(path: &Path, detail: &str) -> AgentError {
    AgentError::Layout {
        path: path.to_path_buf(),
        detail: detail.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const USER_CONFIG: &str = r#"# my codex setup
model = "gpt-5-codex"   # pinned
approval_policy = "on-request"

[features]
web_search = true

[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "./audit-shell.sh"

[mcp_servers.docs]
command = "docs-mcp"
"#;

    fn project_with(config: &str) -> tempfile::TempDir {
        let p = tempfile::tempdir().unwrap();
        fs::create_dir(p.path().join(".codex")).unwrap();
        fs::write(p.path().join(CONFIG_REL), config).unwrap();
        p
    }

    fn read(p: &Path) -> String {
        fs::read_to_string(p.join(CONFIG_REL)).unwrap()
    }

    /// Spec §5.2: shell and file edits (`apply_patch`, which Codex's
    /// `Edit`/`Write` aliases also match). The matcher is an anchored regex.
    #[test]
    fn matcher_covers_shell_and_apply_patch() {
        let list = MATCHER.trim_start_matches("^(").trim_end_matches(")$");
        let tools: Vec<&str> = list.split('|').collect();
        assert_eq!(tools, ["Bash", "apply_patch"]);
    }

    #[test]
    fn install_appends_our_group_and_keeps_comments() {
        let p = project_with(USER_CONFIG);
        assert_eq!(install(p.path()).unwrap(), Change::Updated);
        let text = read(p.path());
        assert!(text.starts_with("# my codex setup\nmodel = \"gpt-5-codex\"   # pinned\n"));
        let doc: DocumentMut = text.parse().unwrap();
        let groups = doc["hooks"]["PreToolUse"].as_array_of_tables().unwrap();
        assert_eq!(groups.len(), 2);
        let ours = groups.get(1).unwrap();
        assert_eq!(ours["matcher"].as_str(), Some(MATCHER));
        let h = ours["hooks"].as_array_of_tables().unwrap().get(0).unwrap();
        assert_eq!(
            h["command"].as_str(),
            Some("saiife check --hook-exit --agent codex")
        );
        assert_eq!(h["timeout"].as_integer(), Some(10));
        assert_eq!(h["statusMessage"].as_str(), Some("saiife guard"));
        assert_eq!(
            doc["mcp_servers"]["docs"]["command"].as_str(),
            Some("docs-mcp")
        );
        assert_eq!(entries(p.path()).unwrap(), vec![expected_entry()]);
    }

    #[test]
    fn install_twice_then_remove_restores_bytes() {
        let p = project_with(USER_CONFIG);
        install(p.path()).unwrap();
        let once = read(p.path());
        assert_eq!(install(p.path()).unwrap(), Change::Unchanged);
        assert_eq!(read(p.path()), once);
        assert_eq!(remove(p.path(), false).unwrap(), Change::Updated);
        assert_eq!(read(p.path()), USER_CONFIG);
    }

    #[test]
    fn fresh_file_has_no_bare_hooks_header_and_is_deleted_again() {
        let p = tempfile::tempdir().unwrap();
        assert_eq!(
            install(p.path()).unwrap(),
            Change::Created {
                created_dirs: vec![".codex".into()]
            }
        );
        let text = read(p.path());
        assert!(text.starts_with("[[hooks.PreToolUse]]\n"), "{text}");
        assert!(!text.contains("[hooks]\n"), "{text}");
        assert_eq!(remove(p.path(), true).unwrap(), Change::Deleted);
        assert!(!p.path().join(CONFIG_REL).exists());
    }

    /// A user handler and saiife's in one [[hooks.PreToolUse]] group: remove
    /// takes only saiife's and keeps the group with the user's handler.
    #[test]
    fn remove_keeps_the_user_handler_in_a_shared_group() {
        let shared = r#"[[hooks.PreToolUse]]
matcher = "^(Bash|apply_patch)$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "./audit-shell.sh"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "saiife check --hook-exit --agent codex"
timeout = 10
"#;
        let p = project_with(shared);
        assert_eq!(entries(p.path()).unwrap().len(), 1);
        assert_eq!(remove(p.path(), true).unwrap(), Change::Updated);
        let doc: DocumentMut = read(p.path()).parse().unwrap();
        let groups = doc["hooks"]["PreToolUse"].as_array_of_tables().unwrap();
        assert_eq!(groups.len(), 1);
        let g = groups.get(0).unwrap();
        assert_eq!(g["matcher"].as_str(), Some(MATCHER));
        let handlers = g["hooks"].as_array_of_tables().unwrap();
        assert_eq!(handlers.len(), 1);
        assert_eq!(
            handlers.get(0).unwrap()["command"].as_str(),
            Some("./audit-shell.sh")
        );
        assert!(entries(p.path()).unwrap().is_empty());
    }

    #[test]
    fn tampered_timeout_changes_the_fingerprint() {
        let p = project_with(USER_CONFIG);
        install(p.path()).unwrap();
        let t = read(p.path()).replace("timeout = 10", "timeout = 0");
        fs::write(p.path().join(CONFIG_REL), t).unwrap();
        let got = entries(p.path()).unwrap();
        assert_eq!(got.len(), 1);
        assert_ne!(got, vec![expected_entry()]);
    }

    const INLINE_IN_TABLE: &str = r#"model = "gpt-5-codex"

[hooks]
PreToolUse = [
  { matcher = "^Bash$", hooks = [{ type = "command", command = "./audit-shell.sh" }] },
]
"#;

    const INLINE_TABLE: &str = r#"hooks = { PreToolUse = [{ matcher = "^Bash$", hooks = [{ type = "command", command = "./audit-shell.sh" }] }] }
"#;

    /// Plan 2 carry-over: an inline layout the user wrote is kept; saiife's
    /// group is appended to it as an inline table, recognized on the next
    /// run, and removed again.
    #[test]
    fn inline_layouts_get_our_group_appended_inline() {
        for user in [INLINE_IN_TABLE, INLINE_TABLE] {
            let p = project_with(user);
            assert_eq!(install(p.path()).unwrap(), Change::Updated, "{user}");
            let text = read(p.path());
            assert!(!text.contains("[[hooks.PreToolUse]]"), "{text}");
            let doc: DocumentMut = text.parse().unwrap();
            let groups = doc["hooks"]["PreToolUse"].as_array().unwrap();
            assert_eq!(groups.len(), 2, "{text}");
            let first = groups.get(0).unwrap().as_inline_table().unwrap();
            assert_eq!(first["matcher"].as_str(), Some("^Bash$"));
            assert_eq!(entries(p.path()).unwrap(), vec![expected_entry()], "{text}");
            assert_eq!(install(p.path()).unwrap(), Change::Unchanged);
            assert_eq!(remove(p.path(), false).unwrap(), Change::Updated);
            assert_eq!(read(p.path()), user, "byte-for-byte");
            assert!(entries(p.path()).unwrap().is_empty());
        }
    }

    /// A saiife handler someone wrote into an inline layout by hand is
    /// replaced like any changed entry, not duplicated.
    #[test]
    fn a_hand_written_inline_saiife_entry_is_replaced() {
        let p = project_with(
            "[hooks]\nPreToolUse = [{ matcher = \"^Bash$\", hooks = [{ type = \"command\", command = \"saiife check --agent codex\", timeout = 0 }] }]\n",
        );
        assert_eq!(entries(p.path()).unwrap().len(), 1);
        assert_ne!(entries(p.path()).unwrap(), vec![expected_entry()]);
        assert_eq!(install(p.path()).unwrap(), Change::Updated);
        assert_eq!(entries(p.path()).unwrap(), vec![expected_entry()]);
        assert_eq!(remove(p.path(), true).unwrap(), Change::Deleted);
    }

    #[test]
    fn inline_hooks_table_without_pre_tool_use_gains_it() {
        let p = project_with("hooks = { Stop = [] }\n");
        assert_eq!(install(p.path()).unwrap(), Change::Updated);
        assert_eq!(entries(p.path()).unwrap(), vec![expected_entry()]);
        assert_eq!(remove(p.path(), false).unwrap(), Change::Updated);
        assert_eq!(read(p.path()), "hooks = { Stop = [] }\n");
    }

    #[test]
    fn other_layouts_and_bad_toml_are_left_untouched() {
        for bad in [
            "hooks = { PreToolUse = 3 }\n",
            "[hooks]\nPreToolUse = [1, 2]\n",
            "model = \n",
            "hooks = 3\n",
        ] {
            let p = project_with(bad);
            assert!(install(p.path()).is_err(), "{bad:?}");
            assert_eq!(read(p.path()), bad, "{bad:?}");
        }
    }

    #[test]
    fn features_hooks_false_is_a_blocker() {
        let p = project_with("[features]\nhooks = false\n");
        let home = tempfile::tempdir().unwrap();
        let found = blockers(p.path(), Some(home.path()));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].setting, "[features] hooks = false");
        let ok = project_with("[features]\nhooks = true\n");
        assert!(blockers(ok.path(), Some(home.path())).is_empty());
    }

    #[test]
    fn unparseable_or_unreadable_config_is_reported() {
        let p = project_with("model = \n");
        let home = tempfile::tempdir().unwrap();
        fs::create_dir_all(home.path().join(".codex/config.toml")).unwrap();
        let found = blockers(p.path(), Some(home.path()));
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found
            .iter()
            .all(|b| b.error.is_some() && b.setting.is_empty()));
    }
}
