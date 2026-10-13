//! Codex: `[[hooks.PreToolUse]]` in `.codex/config.toml`
//! (contract: docs/superpowers/research/2026-10-13-codex-hooks.md).
//!
//! Edited with `toml_edit`, so the user's comments, key order and
//! formatting survive. saiife only reads and writes the array-of-tables
//! form (`[[hooks.PreToolUse]]` with `[[hooks.PreToolUse.hooks]]`); any
//! other layout of `hooks.PreToolUse` is reported, never rewritten.

use std::path::{Path, PathBuf};

use serde_json::Value;
use toml_edit::{value, ArrayOfTables, DocumentMut, Item, Table};

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
    let path = project.join(CONFIG_REL);
    let text = fsutil::read_optional(&path)?;
    let mut doc = parse(&path, text.as_deref().unwrap_or(""))?;
    if fingerprints(&path, &doc)? == [expected_entry()] {
        return Ok(Change::Unchanged);
    }
    strip_ours(&path, &mut doc)?;
    let hooks = doc
        .entry("hooks")
        .or_insert_with(|| {
            let mut t = Table::new();
            t.set_implicit(true);
            Item::Table(t)
        })
        .as_table_mut()
        .ok_or_else(|| layout(&path, "`hooks` is not a table"))?;
    let groups = hooks
        .entry("PreToolUse")
        .or_insert_with(|| Item::ArrayOfTables(ArrayOfTables::new()))
        .as_array_of_tables_mut()
        .ok_or_else(|| {
            layout(
                &path,
                "`hooks.PreToolUse` is not a list of [[hooks.PreToolUse]] tables",
            )
        })?;
    groups.push(group());
    let mut out = doc.to_string();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    fsutil::write(project, CONFIG_REL, &out)
}

/// Remove saiife's handlers. With `delete_if_empty`, a file left with no
/// content is deleted (use only for a file saiife created).
pub fn remove(project: &Path, delete_if_empty: bool) -> Result<Change, AgentError> {
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
    let g = group();
    let handler = g["hooks"]
        .as_array_of_tables()
        .and_then(|a| a.get(0))
        .expect("group() has one handler");
    entry_fingerprint(g.get("matcher"), handler)
}

/// `[features] hooks = false` in the project or user config turns every
/// Codex hook off.
pub fn blockers(project: &Path, home: Option<&Path>) -> Vec<HookBlocker> {
    let mut files = vec![project.join(CONFIG_REL)];
    if let Some(home) = home {
        files.push(home.join(".codex/config.toml"));
    }
    files
        .into_iter()
        .filter(|f| {
            std::fs::read_to_string(f)
                .ok()
                .and_then(|t| t.parse::<DocumentMut>().ok())
                .and_then(|d| d.get("features")?.get("hooks")?.as_bool())
                == Some(false)
        })
        .map(|path: PathBuf| HookBlocker {
            path,
            setting: "[features] hooks = false",
        })
        .collect()
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

fn parse(path: &Path, text: &str) -> Result<DocumentMut, AgentError> {
    text.parse::<DocumentMut>().map_err(|e| AgentError::Parse {
        path: path.to_path_buf(),
        format: "TOML",
        detail: e.to_string().trim().replace('\n', " "),
    })
}

/// `hooks.PreToolUse` as array-of-tables, `None` if absent.
fn groups<'a>(path: &Path, doc: &'a DocumentMut) -> Result<Option<&'a ArrayOfTables>, AgentError> {
    let Some(hooks) = doc.get("hooks") else {
        return Ok(None);
    };
    let Some(pre) = hooks.get("PreToolUse") else {
        return Ok(None);
    };
    pre.as_array_of_tables().map(Some).ok_or_else(|| {
        layout(
            path,
            "`hooks.PreToolUse` is not a list of [[hooks.PreToolUse]] tables",
        )
    })
}

fn fingerprints(path: &Path, doc: &DocumentMut) -> Result<Vec<String>, AgentError> {
    let mut out = Vec::new();
    for g in groups(path, doc)?.into_iter().flat_map(ArrayOfTables::iter) {
        if let Some(handlers) = g.get("hooks").and_then(Item::as_array_of_tables) {
            for h in handlers.iter().filter(|h| is_ours(h)) {
                out.push(entry_fingerprint(g.get("matcher"), h));
            }
        }
    }
    Ok(out)
}

/// Remove saiife handlers; drop groups left with none. Returns the count.
fn strip_ours(path: &Path, doc: &mut DocumentMut) -> Result<usize, AgentError> {
    groups(path, doc)?; // layout check
    let Some(groups) = doc
        .get_mut("hooks")
        .and_then(|h| h.get_mut("PreToolUse"))
        .and_then(Item::as_array_of_tables_mut)
    else {
        return Ok(0);
    };
    let mut removed = 0;
    groups.retain(|g| {
        let Some(handlers) = g.get("hooks").and_then(Item::as_array_of_tables) else {
            return true;
        };
        let ours = handlers.iter().filter(|h| is_ours(h)).count();
        removed += ours;
        !(ours > 0 && ours == handlers.len())
    });
    for g in groups.iter_mut() {
        if let Some(handlers) = g.get_mut("hooks").and_then(Item::as_array_of_tables_mut) {
            handlers.retain(|h| !is_ours(h));
        }
    }
    Ok(removed)
}

/// Drop `hooks.PreToolUse` and then `hooks` if removing saiife left them
/// empty.
fn prune(doc: &mut DocumentMut) {
    let Some(hooks) = doc.get_mut("hooks").and_then(Item::as_table_mut) else {
        return;
    };
    if hooks
        .get("PreToolUse")
        .and_then(Item::as_array_of_tables)
        .is_some_and(ArrayOfTables::is_empty)
    {
        hooks.remove("PreToolUse");
    }
    if hooks.is_empty() {
        doc.remove("hooks");
    }
}

fn is_ours(handler: &Table) -> bool {
    handler
        .get("command")
        .and_then(Item::as_str)
        .is_some_and(is_saiife_command)
}

/// Same scheme as the JSON agents: matcher + handler, as canonical JSON.
fn entry_fingerprint(matcher: Option<&Item>, handler: &Table) -> String {
    fingerprint::of_json(&serde_json::json!({
        "matcher": matcher.map(item_to_json).unwrap_or(Value::Null),
        "handler": table_to_json(handler),
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

    #[test]
    fn other_layouts_and_bad_toml_are_left_untouched() {
        for bad in ["hooks = { PreToolUse = [] }\n", "model = \n", "hooks = 3\n"] {
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
}
