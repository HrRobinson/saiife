//! Shared install/remove/fingerprint logic for agents whose hooks live in a
//! JSON settings file shaped like
//! `{"hooks": {"<Event>": [{"matcher": "…", "hooks": [{"type": "command", …}]}]}}`
//! (Claude Code `PreToolUse`, Gemini CLI `BeforeTool`).
//!
//! The file is parsed with `serde_json` (`preserve_order`), so every key the
//! user wrote stays where it was; it is written back with the indent the file
//! already used. Only handlers that run `saiife check` (or are named
//! `saiife`) are ever touched.

use std::path::Path;

use serde::Serialize;
use serde_json::{Map, Value};

use crate::{fingerprint, fsutil, is_saiife_command, AgentError, Change};

/// One agent's JSON hook layout and the entry saiife writes there.
pub(crate) struct JsonHooks {
    /// Settings file, relative to the project root.
    pub rel: &'static str,
    /// Hook event key under `hooks`.
    pub event: &'static str,
    /// The group `install` adds: `{"matcher": …, "hooks": [handler]}`.
    pub group: fn() -> Value,
}

impl JsonHooks {
    pub fn install(&self, project: &Path) -> Result<Change, AgentError> {
        fsutil::ensure_inside(project, self.rel)?;
        let path = project.join(self.rel);
        let text = fsutil::read_optional(&path)?;
        match self.installed_text(&path, text.as_deref())? {
            None => Ok(Change::Unchanged),
            Some(out) => fsutil::write(project, self.rel, &out),
        }
    }

    /// Remove saiife's handlers. With `delete_if_empty`, a file left as `{}`
    /// is deleted (use only for a file saiife created).
    pub fn remove(&self, project: &Path, delete_if_empty: bool) -> Result<Change, AgentError> {
        fsutil::ensure_inside(project, self.rel)?;
        let path = project.join(self.rel);
        let Some(text) = fsutil::read_optional(&path)? else {
            return Ok(Change::Unchanged);
        };
        match self.removed_text(&path, &text)? {
            None => Ok(Change::Unchanged),
            Some((_, true)) if delete_if_empty => {
                fsutil::remove(project, self.rel)?;
                Ok(Change::Deleted)
            }
            Some((out, _)) => fsutil::write(project, self.rel, &out),
        }
    }

    /// [`JsonHooks::install`] for a machine-wide managed file at an absolute
    /// path (locked mode): no project, symlinks refused, written 0644.
    pub fn install_file(&self, path: &Path) -> Result<Change, AgentError> {
        let text = fsutil::read_managed(path)?;
        match self.installed_text(path, text.as_deref())? {
            None => Ok(Change::Unchanged),
            Some(out) => fsutil::write_managed(path, &out),
        }
    }

    /// [`JsonHooks::remove`] for a managed file; never deletes the file.
    pub fn remove_file(&self, path: &Path) -> Result<Change, AgentError> {
        let Some(text) = fsutil::read_managed(path)? else {
            return Ok(Change::Unchanged);
        };
        match self.removed_text(path, &text)? {
            None => Ok(Change::Unchanged),
            Some((out, _)) => fsutil::write_managed(path, &out),
        }
    }

    /// Fingerprints of saiife's handlers in a managed file.
    pub fn entries_file(&self, path: &Path) -> Result<Vec<String>, AgentError> {
        let Some(text) = fsutil::read_managed(path)? else {
            return Ok(Vec::new());
        };
        let root = parse(path, Some(&text))?;
        self.fingerprints(path, &root)
    }

    /// The text with saiife's group in place, or `None` when the file
    /// already holds exactly that entry and no other of saiife's.
    fn installed_text(
        &self,
        path: &Path,
        text: Option<&str>,
    ) -> Result<Option<String>, AgentError> {
        let mut root = parse(path, text)?;
        if self.fingerprints(path, &root)? == [self.expected()] {
            return Ok(None);
        }
        self.strip_ours(path, &mut root)?;
        event_array(path, &mut root, self.event)?.push((self.group)());
        Ok(Some(render(&root, text)))
    }

    /// The text without saiife's handlers and whether nothing else is left
    /// (`{}`), or `None` when there was nothing of saiife's.
    fn removed_text(&self, path: &Path, text: &str) -> Result<Option<(String, bool)>, AgentError> {
        let mut root = parse(path, Some(text))?;
        if self.strip_ours(path, &mut root)? == 0 {
            return Ok(None);
        }
        prune(&mut root, self.event);
        let empty = root.as_object().is_some_and(Map::is_empty);
        Ok(Some((render(&root, Some(text)), empty)))
    }

    pub fn entries(&self, project: &Path) -> Result<Vec<String>, AgentError> {
        let path = project.join(self.rel);
        let Some(text) = fsutil::read_optional(&path)? else {
            return Ok(Vec::new());
        };
        let root = parse(&path, Some(&text))?;
        self.fingerprints(&path, &root)
    }

    pub fn expected(&self) -> String {
        let group = (self.group)();
        entry_fingerprint(group.get("matcher"), &group["hooks"][0])
    }

    /// Fingerprints of saiife's handlers, in file order.
    fn fingerprints(&self, path: &Path, root: &Value) -> Result<Vec<String>, AgentError> {
        let Some(groups) = root.get("hooks").and_then(|h| h.get(self.event)) else {
            return Ok(Vec::new());
        };
        let Some(groups) = groups.as_array() else {
            return Err(layout(
                path,
                &format!("\"hooks.{}\" is not a list", self.event),
            ));
        };
        let mut out = Vec::new();
        for g in groups {
            if let Some(handlers) = g.get("hooks").and_then(Value::as_array) {
                for h in handlers.iter().filter(|h| is_ours(h)) {
                    out.push(entry_fingerprint(g.get("matcher"), h));
                }
            }
        }
        Ok(out)
    }

    /// Remove every saiife handler; drop groups left with no handler. Returns
    /// how many handlers were removed.
    fn strip_ours(&self, path: &Path, root: &mut Value) -> Result<usize, AgentError> {
        let Some(groups) = root.get_mut("hooks").and_then(|h| h.get_mut(self.event)) else {
            return Ok(0);
        };
        let Some(groups) = groups.as_array_mut() else {
            return Err(layout(
                path,
                &format!("\"hooks.{}\" is not a list", self.event),
            ));
        };
        let mut removed = 0;
        groups.retain_mut(|g| {
            let Some(handlers) = g.get_mut("hooks").and_then(Value::as_array_mut) else {
                return true;
            };
            let before = handlers.len();
            handlers.retain(|h| !is_ours(h));
            let gone = before - handlers.len();
            removed += gone;
            !(gone > 0 && handlers.is_empty())
        });
        Ok(removed)
    }
}

/// A saiife handler: runs `saiife check`, or is named `saiife` (Gemini).
fn is_ours(handler: &Value) -> bool {
    handler
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(is_saiife_command)
        || handler.get("name").and_then(Value::as_str) == Some("saiife")
}

/// Matcher and handler together: changing either (e.g. narrowing the
/// matcher so the hook never fires) counts as tampering.
fn entry_fingerprint(matcher: Option<&Value>, handler: &Value) -> String {
    fingerprint::of_json(&serde_json::json!({
        "matcher": matcher.cloned().unwrap_or(Value::Null),
        "handler": handler,
    }))
}

fn parse(path: &Path, text: Option<&str>) -> Result<Value, AgentError> {
    let text = text.unwrap_or("");
    if text.trim().is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    let v: Value = serde_json::from_str(text).map_err(|e| AgentError::Parse {
        path: path.to_path_buf(),
        format: "JSON",
        detail: e.to_string(),
    })?;
    if !v.is_object() {
        return Err(layout(path, "the top level is not a JSON object"));
    }
    Ok(v)
}

/// `root.hooks.<event>`, created as needed.
fn event_array<'a>(
    path: &Path,
    root: &'a mut Value,
    event: &str,
) -> Result<&'a mut Vec<Value>, AgentError> {
    let obj = root.as_object_mut().expect("parse() checked the root");
    let hooks = obj
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(hooks) = hooks.as_object_mut() else {
        return Err(layout(path, "\"hooks\" is not an object"));
    };
    let groups = hooks
        .entry(event)
        .or_insert_with(|| Value::Array(Vec::new()));
    groups
        .as_array_mut()
        .ok_or_else(|| layout(path, &format!("\"hooks.{event}\" is not a list")))
}

/// Drop `hooks.<event>` and then `hooks` if removing saiife left them empty.
fn prune(root: &mut Value, event: &str) {
    let Some(obj) = root.as_object_mut() else {
        return;
    };
    if let Some(hooks) = obj.get_mut("hooks").and_then(Value::as_object_mut) {
        if hooks
            .get(event)
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        {
            hooks.remove(event);
        }
        if hooks.is_empty() {
            obj.remove("hooks");
        }
    }
}

/// Pretty JSON with the indent the original file used (two spaces if it had
/// none), its line endings (CRLF if it used any) and its trailing newline
/// (kept if there was one or no file).
///
/// Not preserved: a minified (single-line) file comes back pretty-printed,
/// and string escapes are normalized (`"\u00e9"` becomes `"é"`, `"\/"`
/// becomes `"/"`), because the file is re-serialized from parsed values.
/// The content is unchanged; only its spelling differs.
fn render(root: &Value, original: Option<&str>) -> String {
    let indent = original.and_then(detect_indent).unwrap_or("  ");
    let mut buf = Vec::new();
    let fmt = serde_json::ser::PrettyFormatter::with_indent(indent.as_bytes());
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, fmt);
    root.serialize(&mut ser).expect("a JSON value serializes");
    let mut out = String::from_utf8(buf).expect("serde_json writes UTF-8");
    if original.is_none_or(|t| t.ends_with('\n') || t.trim().is_empty()) {
        out.push('\n');
    }
    // serde_json never puts a raw newline inside a string, so every '\n'
    // here is a line break.
    if original.is_some_and(|t| t.contains("\r\n")) {
        out = out.replace('\n', "\r\n");
    }
    out
}

/// Leading whitespace of the first indented line.
fn detect_indent(text: &str) -> Option<&str> {
    text.lines().skip(1).find_map(|l| {
        let n = l.len() - l.trim_start_matches([' ', '\t']).len();
        (n > 0).then(|| &l[..n])
    })
}

fn layout(path: &Path, detail: &str) -> AgentError {
    AgentError::Layout {
        path: path.to_path_buf(),
        detail: detail.to_string(),
    }
}
