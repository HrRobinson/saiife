//! Connector manifests (spec §6.8.1, §8.4): the schema, the built-in list,
//! admin-local manifests and the generic `http` connector (§6.8.2).

use crate::params::ParamType;
use crate::BrokerError;
use saiife_policy::{capability::Capability, ServiceCfg};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::OnceLock;

/// The only schema version this build understands.
pub const SCHEMA_VERSION: u32 = 1;
/// The connector name of the generic HTTP connector; no manifest may use it.
pub const HTTP_CONNECTOR: &str = "http";
const METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE"];
const AUTH_KINDS: &[&str] = &["header", "bearer", "basic"];
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub id: String,
    pub version: u32,
    pub title: String,
    pub base_url: String,
    pub hosts: Vec<String>,
    #[serde(default)]
    pub auth: Vec<AuthSpec>,
    #[serde(default)]
    pub request_headers: Vec<String>,
    #[serde(default)]
    pub params: BTreeMap<String, ParamSpec>,
    #[serde(default)]
    pub operation: Vec<Operation>,
}

/// A service parameter set by the admin (`[services.x.params]`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParamSpec {
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub required: bool,
}

impl ParamSpec {
    pub fn param_type(&self) -> Result<ParamType, BrokerError> {
        ParamType::parse(&self.ty, self.pattern.as_deref())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSpec {
    pub kind: String,
    #[serde(default)]
    pub name: Option<String>,
    /// The vault field holding the credential (`token`, `value`, ...). Not
    /// used for `basic`, which always uses the fields `username` and
    /// `password`; it defaults to empty.
    #[serde(default)]
    pub secret_field: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub id: String,
    pub capability: String,
    #[serde(default)]
    pub qualifier: Option<String>,
    pub kind: OpKind,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub path_params: BTreeMap<String, String>,
    #[serde(default)]
    pub query: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub pagination: Option<Pagination>,
    #[serde(default)]
    pub amount: Option<AmountSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OpKind {
    Read,
    Write,
    Delete,
    Bulk,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum Pagination {
    LinkHeader,
    /// `next` is a JSON path such as `paging.next.after`.
    Cursor {
        param: String,
        next: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AmountSpec {
    pub field: String,
    pub currency_field: String,
    pub unit: Unit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Unit {
    Major,
    Minor,
}

fn bad(m: &str, why: impl std::fmt::Display) -> BrokerError {
    BrokerError::Manifest(format!("{m}: {why}"))
}

/// One segment of a path template: a literal, or `prefix{name}suffix` with
/// exactly one placeholder (so `{order_id}.json` works).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Seg<'a> {
    Lit(&'a str),
    Var {
        prefix: &'a str,
        name: &'a str,
        suffix: &'a str,
    },
}

fn plain(s: &str) -> bool {
    !s.contains(['%', '\\', '?', '#', '{', '}'])
}

pub(crate) fn template_segments(path: &str) -> Result<Vec<Seg<'_>>, String> {
    let rest = path
        .strip_prefix('/')
        .ok_or_else(|| "path must start with /".to_string())?;
    let segs = rest
        .split('/')
        .map(|s| {
            if s.contains(['{', '}']) {
                let err =
                    || format!("segment {s:?}: expected prefix{{name}}suffix with one placeholder");
                let (prefix, tail) = s.split_once('{').ok_or_else(err)?;
                let (name, suffix) = tail.split_once('}').ok_or_else(err)?;
                if !plain(prefix)
                    || !plain(suffix)
                    || name.is_empty()
                    || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                {
                    return Err(err());
                }
                Ok(Seg::Var {
                    prefix,
                    name,
                    suffix,
                })
            } else if s == ".." || s == "." || !plain(s) {
                Err(format!("segment {s:?} is not allowed"))
            } else {
                Ok(Seg::Lit(s))
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let mut seen = BTreeSet::new();
    for s in &segs {
        if let Seg::Var { name, .. } = s {
            if !seen.insert(*name) {
                return Err(format!("placeholder {name} appears twice"));
            }
        }
    }
    Ok(segs)
}

/// The template with placeholder names erased: two operations with the same
/// method and shape would match the same requests.
fn shape<'a>(segs: &[Seg<'a>]) -> Vec<(bool, &'a str, &'a str)> {
    segs.iter()
        .map(|s| match s {
            Seg::Lit(l) => (false, *l, ""),
            Seg::Var { prefix, suffix, .. } => (true, *prefix, *suffix),
        })
        .collect()
}

impl Manifest {
    /// Parses and checks one manifest file.
    pub fn parse(text: &str) -> Result<Manifest, BrokerError> {
        let m: Manifest = toml::from_str(text).map_err(|e| BrokerError::Manifest(e.to_string()))?;
        m.check()?;
        Ok(m)
    }

    /// Structural checks beyond what the schema enforces.
    pub fn check(&self) -> Result<(), BrokerError> {
        let id = &self.id;
        if self.version != SCHEMA_VERSION {
            return Err(bad(id, format!("version must be {SCHEMA_VERSION}")));
        }
        if id.is_empty()
            || !id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return Err(bad(id, "id must match [a-z0-9_-]+"));
        }
        if self.hosts.is_empty() || self.hosts.iter().any(|h| h.is_empty()) {
            return Err(bad(id, "hosts must list at least one host"));
        }
        if !self.base_url.starts_with("https://") {
            return Err(bad(id, "base_url must be https://"));
        }
        for (name, spec) in &self.params {
            spec.param_type()
                .map_err(|e| bad(id, format!("param {name}: {e}")))?;
        }
        for var in braces(&self.base_url).map_err(|e| bad(id, e))? {
            if !self.params.contains_key(var) {
                return Err(bad(id, format!("base_url uses undeclared param {var}")));
            }
        }
        for a in &self.auth {
            if !AUTH_KINDS.contains(&a.kind.as_str()) {
                return Err(bad(id, format!("auth kind {:?} is not supported", a.kind)));
            }
            if a.kind != "basic" && a.secret_field.is_empty() {
                return Err(bad(id, "auth needs a secret_field"));
            }
            if a.kind == "header" && a.name.as_deref().unwrap_or("").is_empty() {
                return Err(bad(id, "auth kind header needs a name"));
            }
        }
        let mut seen = BTreeSet::new();
        let mut shapes = BTreeSet::new();
        for op in &self.operation {
            if let Ok(segs) = template_segments(&op.path) {
                if !shapes.insert((op.method.clone(), shape(&segs))) {
                    return Err(bad(
                        id,
                        format!("operation {}: same method and path shape as another", op.id),
                    ));
                }
            }
            if !seen.insert(op.id.as_str()) {
                return Err(bad(id, format!("duplicate operation {}", op.id)));
            }
            self.check_op(op)
                .map_err(|e| bad(id, format!("operation {}: {e}", op.id)))?;
        }
        Ok(())
    }

    fn check_op(&self, op: &Operation) -> Result<(), String> {
        if op.id.is_empty() {
            return Err("empty id".into());
        }
        Capability::parse(&op.capability).map_err(|e| e.to_string())?;
        if op.qualifier.as_deref() == Some("") {
            return Err("empty qualifier".into());
        }
        if !METHODS.contains(&op.method.as_str()) {
            return Err(format!(
                "method {:?} is not one of {}",
                op.method,
                METHODS.join(", ")
            ));
        }
        let vars: BTreeSet<&str> = template_segments(&op.path)?
            .into_iter()
            .filter_map(|s| match s {
                Seg::Var { name, .. } => Some(name),
                Seg::Lit(_) => None,
            })
            .collect();
        let declared: BTreeSet<&str> = op.path_params.keys().map(String::as_str).collect();
        if vars != declared {
            return Err("path placeholders and path_params differ".into());
        }
        if op.query.keys().any(|k| declared.contains(k.as_str())) {
            return Err("a name is both a path and a query parameter".into());
        }
        if let Some(q) = op.qualifier.as_deref() {
            let vars = braces(q).map_err(|e| format!("qualifier: {e}"))?;
            for v in vars {
                if !declared.contains(v) && !op.query.contains_key(v) {
                    return Err(format!(
                        "qualifier uses {v}, which is not a path or query param of the operation"
                    ));
                }
            }
        }
        for t in op.path_params.values().chain(op.query.values()) {
            ParamType::parse(t, None).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

/// Names between `{` and `}` in a base URL template.
fn braces(s: &str) -> Result<Vec<&str>, String> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(i) = rest.find(['{', '}']) {
        if rest.as_bytes()[i] == b'}' {
            return Err("unbalanced } in base_url".into());
        }
        let end = rest[i..]
            .find('}')
            .ok_or_else(|| "unbalanced { in base_url".to_string())?
            + i;
        out.push(&rest[i + 1..end]);
        rest = &rest[end + 1..];
    }
    Ok(out)
}

/// `(file name, contents)` of every built-in manifest. Later tasks append.
const BUILTIN: &[(&str, &str)] = &[
    ("github.toml", include_str!("../connectors/github.toml")),
    ("hubspot.toml", include_str!("../connectors/hubspot.toml")),
    ("shopify.toml", include_str!("../connectors/shopify.toml")),
];

/// The capability qualifier of `op` for one call: the manifest's template
/// with every `{name}` filled from `params` (the validated call parameters).
/// `None` when the operation has no qualifier or a placeholder has no value
/// (a qualified `allow` then does not match, so the call fails closed).
pub fn qualifier_for(op: &Operation, params: &BTreeMap<String, String>) -> Option<String> {
    let tpl = op.qualifier.as_deref()?;
    let mut out = String::new();
    let mut rest = tpl;
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        let end = rest[i..].find('}')? + i;
        out.push_str(params.get(&rest[i + 1..end])?);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

/// The built-in manifests, parsed once. A bad one panics, which the test
/// `every_builtin_manifest_loads` turns into a build-time failure.
pub fn builtin() -> &'static [Manifest] {
    static CELL: OnceLock<Vec<Manifest>> = OnceLock::new();
    CELL.get_or_init(|| {
        BUILTIN
            .iter()
            .map(|(file, text)| {
                Manifest::parse(text).unwrap_or_else(|e| panic!("built-in manifest {file}: {e}"))
            })
            .collect()
    })
}

/// Loads the admin's manifests from `dir` (`/etc/saiife/connectors`): root
/// owned, not writable by group or others, no symlinks. A missing directory
/// is no manifests. An id equal to a built-in one is refused.
pub fn load_local(dir: &Path) -> Result<Vec<Manifest>, BrokerError> {
    load_local_with(dir, builtin(), 0)
}

/// [`load_local`] with the built-in list and the required owner as inputs
/// (a seam for tests, which cannot create root-owned files).
pub fn load_local_with(
    dir: &Path,
    builtin: &[Manifest],
    owner_uid: u32,
) -> Result<Vec<Manifest>, BrokerError> {
    use std::os::unix::fs::MetadataExt;
    let err = |p: &Path, why: &str| BrokerError::Manifest(format!("{}: {why}", p.display()));
    // Root for the locked daemon, the user for the personal broker.
    let who = if owner_uid == 0 { "root" } else { "this user" };
    let owned = format!("must be owned by {who} and not writable by others");
    let dmeta = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(err(dir, &e.to_string())),
    };
    if !dmeta.is_dir() {
        return Err(err(dir, "not a directory"));
    }
    if dmeta.uid() != owner_uid || dmeta.mode() & 0o022 != 0 {
        return Err(err(dir, &owned));
    }
    let mut names = Vec::new();
    for e in std::fs::read_dir(dir).map_err(|e| err(dir, &e.to_string()))? {
        let e = e.map_err(|e| err(dir, &e.to_string()))?;
        let name = e.file_name();
        if name.to_string_lossy().ends_with(".toml") {
            names.push(name);
        }
    }
    names.sort();
    let mut out: Vec<Manifest> = Vec::new();
    for n in names {
        let path = dir.join(&n);
        let meta = std::fs::symlink_metadata(&path).map_err(|e| err(&path, &e.to_string()))?;
        if !meta.file_type().is_file() {
            return Err(err(&path, "not a regular file (symlinks are not followed)"));
        }
        if meta.uid() != owner_uid || meta.mode() & 0o022 != 0 {
            return Err(err(&path, &owned));
        }
        if meta.len() > MAX_MANIFEST_BYTES {
            return Err(err(&path, "larger than 1 MiB"));
        }
        let text = std::fs::read_to_string(&path).map_err(|e| err(&path, &e.to_string()))?;
        let m = Manifest::parse(&text).map_err(|e| err(&path, &e.to_string()))?;
        if m.id == HTTP_CONNECTOR || builtin.iter().any(|b| b.id == m.id) {
            return Err(BrokerError::ShadowsBuiltin(m.id));
        }
        if out.iter().any(|o| o.id == m.id) {
            return Err(err(&path, "duplicate connector id"));
        }
        out.push(m);
    }
    Ok(out)
}

/// The generic `http` connector (§6.8.2): a manifest built from the
/// service's own `base_url`, `auth` and `[[operation]]` entries.
pub fn from_http_service(name: &str, svc: &ServiceCfg) -> Result<Manifest, BrokerError> {
    let fail = |why: String| BrokerError::Manifest(format!("service {name}: {why}"));
    if svc.connector != HTTP_CONNECTOR {
        return Err(fail("connector is not http".into()));
    }
    let base = svc
        .base_url
        .clone()
        .ok_or_else(|| fail("an http service needs base_url".into()))?;
    let rest = base
        .strip_prefix("https://")
        .ok_or_else(|| fail("base_url must be https://".into()))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return Err(fail("base_url may not hold credentials".into()));
    }
    if base.contains(['{', '}']) {
        return Err(fail("base_url may not hold placeholders".into()));
    }
    let host = match authority.rsplit_once(':') {
        Some((h, port)) if port.bytes().all(|b| b.is_ascii_digit()) && !port.is_empty() => h,
        _ => authority,
    };
    if host.is_empty() || host.contains(['[', ']']) {
        return Err(fail("base_url has no usable host".into()));
    }
    let auth = match &svc.auth {
        None => Vec::new(),
        Some(a) => vec![AuthSpec {
            kind: a.kind.clone(),
            name: a.name.clone(),
            // header {value}, bearer {token}; basic uses the vault fields
            // username and password and no secret_field.
            secret_field: match a.kind.as_str() {
                "header" => "value",
                "bearer" => "token",
                _ => "",
            }
            .to_string(),
        }],
    };
    let mut operation = Vec::new();
    for o in &svc.operation {
        let kind = match o.kind.as_str() {
            "read" => OpKind::Read,
            "write" => OpKind::Write,
            "delete" => OpKind::Delete,
            "bulk" => OpKind::Bulk,
            other => return Err(fail(format!("operation {}: kind {other:?}", o.id))),
        };
        let path_params = template_segments(&o.path)
            .map_err(|e| fail(format!("operation {}: {e}", o.id)))?
            .into_iter()
            .filter_map(|s| match s {
                Seg::Var { name, .. } => Some((name.to_string(), "string".to_string())),
                Seg::Lit(_) => None,
            })
            .collect();
        operation.push(Operation {
            id: o.id.clone(),
            capability: o.capability.clone(),
            qualifier: None,
            kind,
            method: o.method.clone(),
            path: o.path.clone(),
            path_params,
            query: o
                .query
                .iter()
                .map(|q| (q.clone(), "string".to_string()))
                .collect(),
            body: o.body.clone(),
            pagination: None,
            amount: None,
        });
    }
    let m = Manifest {
        id: HTTP_CONNECTOR.to_string(),
        version: SCHEMA_VERSION,
        title: format!("HTTP service {name}"),
        base_url: base.clone(),
        hosts: vec![host.to_string()],
        auth,
        request_headers: vec!["Content-Type".into(), "Accept".into()],
        params: BTreeMap::new(),
        operation,
    };
    m.check().map_err(|e| fail(e.to_string()))?;
    Ok(m)
}
