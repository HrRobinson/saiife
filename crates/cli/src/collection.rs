//! Collections (spec §6.12, plan 14 decision 11): saved, named requests in
//! `.saiife/collections/<name>.toml`. They are named requests, not a flow
//! engine: `saiife api collection run` fills the `{{var}}` placeholders and
//! sends each step as one ordinary `api.call`, so every step goes through
//! the full pipeline (scope, decide, limits, approvals, audit) and a
//! collection can do nothing its steps could not do one by one.
//!
//! An agent may write a collection, so the file is untrusted:
//! - `{{var}}` is allowed only in `params` values and in string values of
//!   the optional inline `body` table, never in `service`, `operation` or a
//!   key.
//! - A filled value is literal: it is never scanned again, so a value such
//!   as `}}{{other}}` stays as it is.
//! - A missing or an unused variable is an error before any step runs.
//!
//! Errors name variables and steps, never a value.

use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Where collections live, relative to the project root.
pub const DIR_REL: &str = ".saiife/collections";
/// The most steps a collection may have.
pub const MAX_STEPS: usize = 32;
/// The largest collection file read.
pub const MAX_FILE_BYTES: u64 = 64 * 1024;
/// The longest variable name (`[a-z_][a-z0-9_]{0,31}`).
const MAX_VAR: usize = 32;

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Collection {
    pub name: String,
    #[serde(default)]
    pub step: Vec<Step>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub service: String,
    pub operation: String,
    #[serde(default)]
    pub params: BTreeMap<String, String>,
    /// A JSON body for the step, written as an inline TOML table.
    #[serde(default)]
    pub body: Option<toml::Table>,
}

/// A step with its placeholders filled: what one `api.call` sends.
#[derive(Debug, Clone, PartialEq)]
pub struct FilledStep {
    pub service: String,
    pub operation: String,
    pub params: BTreeMap<String, String>,
    pub body: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectionError {
    /// The name is not `[a-z0-9_-]{1,64}`.
    BadName,
    NotFound(PathBuf),
    Io(PathBuf, String),
    TooLarge(PathBuf),
    Parse(PathBuf, String),
    /// `name` in the file is not its file stem.
    NameMismatch {
        file: String,
    },
    NoSteps,
    TooManySteps(usize),
    /// A placeholder where none may be (`service`, `operation`, a key).
    PlaceholderNotAllowed {
        step: usize,
        field: String,
    },
    /// A `{{` that does not start a `{{var}}` placeholder.
    BadPlaceholder {
        step: usize,
        field: String,
    },
    /// A body value TOML has and JSON has not (a date or time).
    BadBody {
        step: usize,
        field: String,
    },
    /// A `k=v` whose name is not a variable name.
    BadVar(String),
    /// A variable given twice.
    Duplicate(String),
    /// An argument that is not `k=v`.
    NotKv,
    Missing(Vec<String>),
    Unused(Vec<String>),
}

impl std::fmt::Display for CollectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use CollectionError::*;
        match self {
            BadName => write!(f, "a collection name is [a-z0-9_-], 1 to 64 characters"),
            NotFound(p) => write!(f, "no collection {}", p.display()),
            Io(p, e) => write!(f, "cannot read {}: {e}", p.display()),
            TooLarge(p) => write!(
                f,
                "{} is larger than {} KiB",
                p.display(),
                MAX_FILE_BYTES / 1024
            ),
            Parse(p, e) => write!(f, "{}: {e}", p.display()),
            NameMismatch { file } => {
                write!(f, "{file}: name must equal the file name without .toml")
            }
            NoSteps => write!(f, "the collection has no [[step]]"),
            TooManySteps(n) => write!(f, "{n} steps; a collection has at most {MAX_STEPS}"),
            PlaceholderNotAllowed { step, field } => write!(
                f,
                "step {step}: {field} cannot hold a {{{{placeholder}}}} (only params values and body strings can)"
            ),
            BadPlaceholder { step, field } => write!(
                f,
                "step {step}: {field}: `{{{{` must start a {{{{var}}}} placeholder ([a-z_][a-z0-9_]{{0,31}})"
            ),
            BadBody { step, field } => write!(
                f,
                "step {step}: body {field}: dates and times have no JSON form; use a string"
            ),
            BadVar(k) => write!(
                f,
                "{k:?} is not a variable name ([a-z_][a-z0-9_]{{0,31}})"
            ),
            Duplicate(k) => write!(f, "{k} is given twice"),
            NotKv => write!(f, "variables are k=v"),
            Missing(v) => write!(f, "no value for {}", list(v)),
            Unused(v) => write!(f, "the collection does not use {}", list(v)),
        }
    }
}

impl std::error::Error for CollectionError {}

fn list(v: &[String]) -> String {
    v.iter()
        .map(|n| format!("{{{{{n}}}}}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A collection name: `[a-z0-9_-]{1,64}` (what the daemon accepts too).
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
}

/// A variable name: `[a-z_][a-z0-9_]{0,31}`.
pub fn valid_var(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_VAR
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

/// The collections directory of `project_root`.
pub fn dir(project_root: &Path) -> PathBuf {
    project_root.join(DIR_REL)
}

/// Read `<project_root>/.saiife/collections/<name>.toml` and check it
/// (decision 11). Placeholders are checked here too, so a collection that
/// loads can only fail to fill for its variables.
pub fn load(project_root: &Path, name: &str) -> Result<Collection, CollectionError> {
    if !valid_name(name) {
        return Err(CollectionError::BadName);
    }
    load_path(&dir(project_root).join(format!("{name}.toml")))
}

/// [`load`] of one file; the name is its stem.
pub fn load_path(path: &Path) -> Result<Collection, CollectionError> {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_string();
    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(CollectionError::NotFound(path.to_path_buf()))
        }
        Err(e) => return Err(CollectionError::Io(path.to_path_buf(), e.to_string())),
    };
    let meta = file
        .metadata()
        .map_err(|e| CollectionError::Io(path.to_path_buf(), e.to_string()))?;
    if !meta.is_file() {
        return Err(CollectionError::Io(
            path.to_path_buf(),
            "not a regular file".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| CollectionError::Io(path.to_path_buf(), e.to_string()))?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(CollectionError::TooLarge(path.to_path_buf()));
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| CollectionError::Parse(path.to_path_buf(), "not UTF-8".into()))?;
    let c: Collection = toml::from_str(&text)
        .map_err(|e| CollectionError::Parse(path.to_path_buf(), e.message().to_string()))?;
    if !valid_name(&c.name) || c.name != stem {
        return Err(CollectionError::NameMismatch { file: file_name });
    }
    check(&c)?;
    Ok(c)
}

/// The checks a parse cannot make: step count, and placeholders only where
/// they are allowed and well formed.
pub fn check(c: &Collection) -> Result<(), CollectionError> {
    if c.step.is_empty() {
        return Err(CollectionError::NoSteps);
    }
    if c.step.len() > MAX_STEPS {
        return Err(CollectionError::TooManySteps(c.step.len()));
    }
    for (i, s) in c.step.iter().enumerate() {
        let n = i + 1;
        let refuse = |field: &str| CollectionError::PlaceholderNotAllowed {
            step: n,
            field: field.to_string(),
        };
        if s.service.contains("{{") {
            return Err(refuse("service"));
        }
        if s.operation.contains("{{") {
            return Err(refuse("operation"));
        }
        for (k, v) in &s.params {
            if k.contains("{{") {
                return Err(refuse("a params key"));
            }
            scan(v, n, &format!("params.{k}"), &mut |_| None)?;
        }
        if let Some(b) = &s.body {
            check_table(b, n, "")?;
        }
    }
    Ok(())
}

fn check_table(t: &toml::Table, step: usize, at: &str) -> Result<(), CollectionError> {
    for (k, v) in t {
        let field = join(at, k);
        if k.contains("{{") {
            return Err(CollectionError::PlaceholderNotAllowed {
                step,
                field: "a body key".into(),
            });
        }
        check_value(v, step, &field)?;
    }
    Ok(())
}

fn check_value(v: &toml::Value, step: usize, field: &str) -> Result<(), CollectionError> {
    match v {
        toml::Value::String(s) => scan(s, step, field, &mut |_| None).map(|_| ()),
        toml::Value::Array(a) => a
            .iter()
            .enumerate()
            .try_for_each(|(i, x)| check_value(x, step, &format!("{field}[{i}]"))),
        toml::Value::Table(t) => check_table(t, step, field),
        toml::Value::Datetime(_) => Err(CollectionError::BadBody {
            step,
            field: field.to_string(),
        }),
        _ => Ok(()),
    }
}

fn join(at: &str, k: &str) -> String {
    if at.is_empty() {
        k.to_string()
    } else {
        format!("{at}.{k}")
    }
}

/// One pass over `s`: each `{{var}}` is handed to `fill`, which returns
/// the text that takes its place; everything else is copied. Any other
/// `{{` is an error. The output is never scanned again.
fn scan(
    s: &str,
    step: usize,
    field: &str,
    fill: &mut dyn FnMut(&str) -> Option<String>,
) -> Result<String, CollectionError> {
    let bad = || CollectionError::BadPlaceholder {
        step,
        field: field.to_string(),
    };
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("{{") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 2..];
        let end = after.find("}}").ok_or_else(bad)?;
        let name = &after[..end];
        if !valid_var(name) {
            return Err(bad());
        }
        // `None`: checking only, or a missing variable (reported later).
        if let Some(v) = fill(name) {
            out.push_str(&v);
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Fill every step's placeholders from `vars` (decision 11). Every variable
/// the collection uses must be given, and every one given must be used;
/// either error comes before any step can run. A value is put in as it is
/// and never expanded again.
pub fn fill(
    c: &Collection,
    vars: &BTreeMap<String, String>,
) -> Result<Vec<FilledStep>, CollectionError> {
    check(c)?;
    if let Some(k) = vars.keys().find(|k| !valid_var(k)) {
        return Err(CollectionError::BadVar(k.clone()));
    }
    let mut used = BTreeSet::new();
    let mut missing = BTreeSet::new();
    let mut lookup = |name: &str| -> Option<String> {
        used.insert(name.to_string());
        let v = vars.get(name).cloned();
        if v.is_none() {
            missing.insert(name.to_string());
        }
        v
    };
    let mut out = Vec::with_capacity(c.step.len());
    for (i, s) in c.step.iter().enumerate() {
        let n = i + 1;
        let mut params = BTreeMap::new();
        for (k, v) in &s.params {
            params.insert(k.clone(), scan(v, n, &format!("params.{k}"), &mut lookup)?);
        }
        let body = match &s.body {
            None => None,
            Some(t) => Some(fill_table(t, n, "", &mut lookup)?),
        };
        out.push(FilledStep {
            service: s.service.clone(),
            operation: s.operation.clone(),
            params,
            body,
        });
    }
    if !missing.is_empty() {
        return Err(CollectionError::Missing(missing.into_iter().collect()));
    }
    let unused: Vec<String> = vars
        .keys()
        .filter(|k| !used.contains(*k))
        .cloned()
        .collect();
    if !unused.is_empty() {
        return Err(CollectionError::Unused(unused));
    }
    Ok(out)
}

fn fill_table(
    t: &toml::Table,
    step: usize,
    at: &str,
    lookup: &mut dyn FnMut(&str) -> Option<String>,
) -> Result<Value, CollectionError> {
    let mut m = serde_json::Map::new();
    for (k, v) in t {
        let field = join(at, k);
        m.insert(k.clone(), fill_value(v, step, &field, lookup)?);
    }
    Ok(Value::Object(m))
}

fn fill_value(
    v: &toml::Value,
    step: usize,
    field: &str,
    lookup: &mut dyn FnMut(&str) -> Option<String>,
) -> Result<Value, CollectionError> {
    Ok(match v {
        toml::Value::String(s) => Value::String(scan(s, step, field, lookup)?),
        toml::Value::Integer(i) => Value::from(*i),
        toml::Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(Value::Number)
            .ok_or_else(|| CollectionError::BadBody {
                step,
                field: field.to_string(),
            })?,
        toml::Value::Boolean(b) => Value::Bool(*b),
        toml::Value::Array(a) => Value::Array(
            a.iter()
                .enumerate()
                .map(|(i, x)| fill_value(x, step, &format!("{field}[{i}]"), lookup))
                .collect::<Result<_, _>>()?,
        ),
        toml::Value::Table(t) => fill_table(t, step, field, lookup)?,
        toml::Value::Datetime(_) => {
            return Err(CollectionError::BadBody {
                step,
                field: field.to_string(),
            })
        }
    })
}

/// Every `*.toml` in the collections directory, sorted by file name, each
/// loaded (or its error). No directory: none.
pub fn list_all(project_root: &Path) -> Vec<(String, Result<Collection, CollectionError>)> {
    let Ok(rd) = std::fs::read_dir(dir(project_root)) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    paths.sort();
    paths
        .into_iter()
        .map(|p| {
            let stem = p
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            (stem, load_path(&p))
        })
        .collect()
}

/// `k=v` arguments as variables; `Err` names the argument that is not
/// `k=v` (never its value).
pub fn parse_vars(args: &[String]) -> Result<BTreeMap<String, String>, CollectionError> {
    let mut vars = BTreeMap::new();
    for kv in args {
        match kv.split_once('=') {
            Some((k, v)) if valid_var(k) => {
                if vars.insert(k.to_string(), v.to_string()).is_some() {
                    return Err(CollectionError::Duplicate(k.to_string()));
                }
            }
            Some((k, _)) => return Err(CollectionError::BadVar(k.to_string())),
            None => return Err(CollectionError::NotKv),
        }
    }
    Ok(vars)
}
