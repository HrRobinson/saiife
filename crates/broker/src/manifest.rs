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
const AUTH_KINDS: &[&str] = &["header", "bearer", "basic", "basic_token", "oauth2"];
/// The body formats of `Operation::body`. `text` is for `transport = "mail"`.
const BODY_FORMATS: &[&str] = &["json", "form", "text"];
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub id: String,
    pub version: u32,
    pub title: String,
    pub base_url: String,
    /// Literal hosts and `*.suffix` globs, or whole-host placeholders
    /// `{param}` (decision 1).
    pub hosts: Vec<String>,
    #[serde(default)]
    pub auth: Vec<AuthSpec>,
    #[serde(default)]
    pub request_headers: Vec<String>,
    /// Headers the broker sets after the agent's, winning over them: a
    /// literal, or text with `{param}` filled from a required service param.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub transport: Transport,
    #[serde(default)]
    pub params: BTreeMap<String, ParamSpec>,
    #[serde(default)]
    pub operation: Vec<Operation>,
}

/// How the connector reaches its upstream. `mail` (SMTP and IMAP) is
/// refused by [`Manifest::check`] until it is built.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    #[default]
    Https,
    Mail,
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
    /// `header` only: printable ASCII put before the secret (`Bot `,
    /// `Token token=`).
    #[serde(default)]
    pub prefix: Option<String>,
    /// `oauth2` only: the token endpoint's path on the base URL's host.
    #[serde(default)]
    pub token_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
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
    /// `json`, `form` (Stripe-style `a[b]=v`) or `text` (mail only).
    #[serde(default)]
    pub body: Option<String>,
    /// Typed call params placed into a built body; a dotted name nests
    /// (`incident.title`). With any of `body_params`, `body_const` or
    /// `graphql` the body is built, and an agent body is refused.
    #[serde(default)]
    pub body_params: BTreeMap<String, String>,
    /// Fixed body fields, by dotted name.
    #[serde(default)]
    pub body_const: BTreeMap<String, toml::Value>,
    /// A fixed GraphQL document: the body is `{"query": <this>,
    /// "variables": <built>}`. Such an operation is named-only.
    #[serde(default)]
    pub graphql: Option<String>,
    #[serde(default)]
    pub pagination: Option<Pagination>,
    #[serde(default)]
    pub amount: Option<AmountSpec>,
}

impl Operation {
    /// The body is built from `body_params`, `body_const` and `graphql`.
    pub fn builds_body(&self) -> bool {
        !self.body_params.is_empty() || !self.body_const.is_empty() || self.graphql.is_some()
    }
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
    /// `next` is a JSON path such as `paging.next.after`; a segment may end
    /// in `[-1]`, the last array element (`data[-1].id`). `more` is the
    /// path of a JSON bool: `false` (or missing) is the last page.
    Cursor {
        param: String,
        next: String,
        #[serde(default)]
        more: Option<String>,
    },
    /// The next `param` is `body[param] + body[limit_field]` while
    /// `body[more]` is `true`.
    Offset {
        param: String,
        limit_field: String,
        more: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AmountSpec {
    pub field: String,
    /// The body path of the currency. Exactly one of this and
    /// `currency_param` is set.
    #[serde(default)]
    pub currency_field: Option<String>,
    /// A manifest param (set by the admin) holding the currency.
    #[serde(default)]
    pub currency_param: Option<String>,
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
        if self.transport == Transport::Mail {
            return Err(bad(id, "transport mail is not supported in this build"));
        }
        for var in braces(&self.base_url).map_err(|e| bad(id, e))? {
            if !self.params.contains_key(var) {
                return Err(bad(id, format!("base_url uses undeclared param {var}")));
            }
        }
        self.check_hosts().map_err(|e| bad(id, e))?;
        for a in &self.auth {
            check_auth(a).map_err(|e| bad(id, e))?;
        }
        self.check_headers().map_err(|e| bad(id, e))?;
        let mut seen = BTreeSet::new();
        let mut shapes = BTreeSet::new();
        for op in &self.operation {
            // A GraphQL operation is named-only (never matched by path), so
            // several may share one endpoint.
            let segs = match op.graphql {
                None => template_segments(&op.path).ok(),
                Some(_) => None,
            };
            if let Some(segs) = segs {
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
        if op
            .body_params
            .keys()
            .any(|k| declared.contains(k.as_str()) || op.query.contains_key(k))
        {
            return Err("a name is both a body and a path or query parameter".into());
        }
        if let Some(q) = op.qualifier.as_deref() {
            let vars = braces(q).map_err(|e| format!("qualifier: {e}"))?;
            for v in vars {
                if !declared.contains(v)
                    && !op.query.contains_key(v)
                    && !op.body_params.contains_key(v)
                {
                    return Err(format!(
                        "qualifier uses {v}, which is not a path, query or body param of the operation"
                    ));
                }
            }
        }
        for t in op
            .path_params
            .values()
            .chain(op.query.values())
            .chain(op.body_params.values())
        {
            ParamType::parse(t, None).map_err(|e| e.to_string())?;
        }
        self.check_body(op)?;
        if let Some(a) = &op.amount {
            match (&a.currency_field, &a.currency_param) {
                (Some(_), None) => {}
                (None, Some(p)) if self.params.contains_key(p) => {}
                (None, Some(p)) => {
                    return Err(format!("amount currency_param {p} is not a declared param"))
                }
                _ => {
                    return Err(
                        "amount needs exactly one of currency_field and currency_param".into(),
                    )
                }
            }
        }
        match &op.pagination {
            Some(Pagination::Cursor { param, next, more }) => {
                next_param_ok(op, param)?;
                json_path_ok(next, true)?;
                if let Some(m) = more {
                    json_path_ok(m, false)?;
                }
            }
            Some(Pagination::Offset {
                param,
                limit_field,
                more,
            }) => {
                next_param_ok(op, param)?;
                for p in [param, limit_field, more] {
                    json_path_ok(p, false)?;
                }
            }
            Some(Pagination::LinkHeader) | None => {}
        }
        Ok(())
    }

    /// The body format and the built-body keys of `op`.
    fn check_body(&self, op: &Operation) -> Result<(), String> {
        if let Some(b) = op.body.as_deref() {
            if !BODY_FORMATS.contains(&b) {
                return Err(format!(
                    "body {b:?} is not one of {}",
                    BODY_FORMATS.join(", ")
                ));
            }
            if b == "text" && self.transport != Transport::Mail {
                return Err("body = \"text\" is for transport = \"mail\" only".into());
            }
        }
        if op.builds_body() && !matches!(op.body.as_deref(), Some("json" | "form")) {
            return Err(
                "body_params, body_const and graphql need body = \"json\" or \"form\"".into(),
            );
        }
        // The amount is read from the JSON the broker encodes. A form body
        // the agent shapes could still decode upstream differently from that
        // JSON, so an amount-capped form operation must build its body.
        if op.amount.is_some() && op.body.as_deref() == Some("form") && !op.builds_body() {
            return Err("an amount on a form body needs a built body (body_params)".into());
        }
        if let Some(q) = &op.graphql {
            if op.body.as_deref() != Some("json") {
                return Err("graphql needs body = \"json\"".into());
            }
            if q.trim().is_empty() {
                return Err("graphql is empty".into());
            }
        }
        let keys: Vec<&str> = op
            .body_params
            .keys()
            .chain(op.body_const.keys())
            .map(String::as_str)
            .collect();
        for k in &keys {
            if k.split('.').any(|s| {
                s.is_empty()
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            }) {
                return Err(format!(
                    "body key {k:?}: each dotted part must be [A-Za-z0-9_-]+"
                ));
            }
        }
        for (i, a) in keys.iter().enumerate() {
            for b in &keys[i + 1..] {
                let nests =
                    |x: &str, y: &str| y.strip_prefix(x).is_some_and(|r| r.starts_with('.'));
                if a == b || nests(a, b) || nests(b, a) {
                    return Err(format!("body keys {a:?} and {b:?} overlap"));
                }
            }
        }
        Ok(())
    }

    /// The host part of `base_url` as written (placeholders unfilled).
    fn base_host_template(&self) -> Option<&str> {
        let rest = self.base_url.strip_prefix("https://")?;
        rest.split(['/', '?', '#']).next()
    }

    /// The service param that is the whole base URL host (`https://{host}/...`),
    /// whose value must be a bare hostname.
    pub fn whole_host_param(&self) -> Option<&str> {
        self.base_host_template().and_then(whole_placeholder)
    }

    /// Decision 1: either fixed hosts and globs, or whole-host `{param}`
    /// entries, each a required param with an anchored pattern, one of which
    /// is exactly the base URL host.
    fn check_hosts(&self) -> Result<(), String> {
        let placeholders: Vec<&str> = self
            .hosts
            .iter()
            .filter_map(|h| whole_placeholder(h))
            .collect();
        if placeholders.is_empty() {
            if let Some(h) = self.hosts.iter().find(|h| h.contains(['{', '}'])) {
                return Err(format!("host {h:?}: a placeholder must be the whole host"));
            }
            return Ok(());
        }
        if placeholders.len() != self.hosts.len() {
            return Err("hosts may not mix {param} entries with fixed hosts".into());
        }
        for p in &placeholders {
            let spec = self
                .params
                .get(*p)
                .ok_or_else(|| format!("host placeholder {{{p}}} is not a declared param"))?;
            if !spec.required {
                return Err(format!("host param {p} must be required"));
            }
            match spec.pattern.as_deref() {
                Some(pat) if pat.starts_with('^') && pat.ends_with('$') => {}
                _ => {
                    return Err(format!(
                        "host param {p} needs an anchored hostname pattern (^...$)"
                    ))
                }
            }
        }
        match self.whole_host_param() {
            Some(p) if placeholders.contains(&p) => Ok(()),
            _ => Err("with {param} hosts, the base_url host must be exactly one of them".into()),
        }
    }

    /// Fixed headers: valid names the broker does not own, printable ASCII
    /// values, and placeholders that are required params.
    fn check_headers(&self) -> Result<(), String> {
        let auth_names: Vec<String> = self
            .auth
            .iter()
            .map(|a| match a.kind.as_str() {
                "header" => a.name.as_deref().unwrap_or("").to_ascii_lowercase(),
                _ => "authorization".to_string(),
            })
            .collect();
        for (name, value) in &self.headers {
            let h = http::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| format!("header {name:?}: not a valid header name"))?;
            let lower = h.as_str();
            if crate::request::ALWAYS_DROPPED.contains(&lower)
                || auth_names.iter().any(|a| a == lower)
            {
                return Err(format!(
                    "header {name}: set by the broker, not the manifest"
                ));
            }
            if !value.bytes().all(|b| (0x20..0x7f).contains(&b)) {
                return Err(format!("header {name}: the value must be printable ASCII"));
            }
            for var in braces(value).map_err(|e| format!("header {name}: {e}"))? {
                match self.params.get(var) {
                    Some(spec) if spec.required => {}
                    _ => {
                        return Err(format!(
                            "header {name}: {{{var}}} must be a required declared param"
                        ))
                    }
                }
            }
        }
        Ok(())
    }
}

/// The checks of one auth entry (decision 5).
fn check_auth(a: &AuthSpec) -> Result<(), String> {
    if !AUTH_KINDS.contains(&a.kind.as_str()) {
        return Err(format!("auth kind {:?} is not supported", a.kind));
    }
    if !matches!(a.kind.as_str(), "basic" | "oauth2") && a.secret_field.is_empty() {
        return Err("auth needs a secret_field".into());
    }
    if a.kind == "header" && a.name.as_deref().unwrap_or("").is_empty() {
        return Err("auth kind header needs a name".into());
    }
    if let Some(p) = &a.prefix {
        if a.kind != "header" {
            return Err("auth prefix is only for kind header".into());
        }
        if p.is_empty() || !p.bytes().all(|b| (0x20..0x7f).contains(&b)) {
            return Err("auth prefix must be printable ASCII".into());
        }
    }
    match (&a.token_path, a.kind == "oauth2") {
        (Some(_), false) => return Err("token_path is only for kind oauth2".into()),
        (None, true) => return Err("auth kind oauth2 needs a token_path".into()),
        (Some(t), true) => {
            let ok = t.starts_with('/')
                && !t.contains("..")
                && !t.contains("//")
                && t.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/-._~".contains(&b));
            if !ok {
                return Err("token_path must be a plain absolute path".into());
            }
        }
        (None, false) => {}
    }
    Ok(())
}

/// The next-page parameter must be one the operation takes: a query param,
/// or a body param of a built (GraphQL) body, where a cursor is a variable.
fn next_param_ok(op: &Operation, param: &str) -> Result<(), String> {
    if op.query.contains_key(param) || op.body_params.contains_key(param) {
        Ok(())
    } else {
        Err(format!(
            "pagination param {param} is not a query or body param of the operation"
        ))
    }
}

/// `x` when `h` is exactly `{x}` with a param-like name.
fn whole_placeholder(h: &str) -> Option<&str> {
    let name = h.strip_prefix('{')?.strip_suffix('}')?;
    (!name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        .then_some(name)
}

/// A dotted JSON path of object keys; with `last_ok`, a part may end in
/// `[-1]` (the last array element).
fn json_path_ok(p: &str, last_ok: bool) -> Result<(), String> {
    for seg in p.split('.') {
        let key = match seg.strip_suffix("[-1]") {
            Some(k) if last_ok => k,
            _ => seg,
        };
        if key.is_empty() || key.contains(['[', ']']) {
            return Err(format!("JSON path {p:?}: bad part {seg:?}"));
        }
    }
    Ok(())
}

/// Names between `{` and `}` in a template.
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

// `BUILTIN`: `(file name, contents)` of every `connectors/*.toml` but
// `test-echo.toml`, sorted, written by `build.rs`.
include!(concat!(env!("OUT_DIR"), "/builtin.rs"));

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
            prefix: None,
            token_path: None,
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
            body_params: BTreeMap::new(),
            body_const: BTreeMap::new(),
            graphql: None,
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
        headers: BTreeMap::new(),
        transport: Transport::Https,
        params: BTreeMap::new(),
        operation,
    };
    m.check().map_err(|e| fail(e.to_string()))?;
    Ok(m)
}
