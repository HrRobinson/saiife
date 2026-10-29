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
const METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];
const AUTH_KINDS: &[&str] = &[
    "header",
    "bearer",
    "basic",
    "basic_token",
    "oauth2",
    "aws_sigv4",
    "gcp_sa",
    "azure_sp",
];
/// The cloud auth kinds (plan 15): the daemon signs or mints the credential
/// from the whole vault entry, so none takes a `secret_field`.
pub const CLOUD_AUTH_KINDS: &[&str] = &["aws_sigv4", "gcp_sa", "azure_sp"];
/// Headers the SigV4 signer sets: never a manifest's or an operation's.
pub const SIGV4_HEADERS: &[&str] = &["x-amz-date", "x-amz-security-token", "x-amz-content-sha256"];
/// The body formats of `Operation::body`. `text` is for `transport = "mail"`;
/// `raw` is the agent's bytes as they are, never parsed.
const BODY_FORMATS: &[&str] = &["json", "form", "text", "raw"];
/// The operation param type of an object key that keeps its `/` (S3,
/// Azure blobs): the last whole path segment, encoded segment by segment.
pub const OBJECT_KEY: &str = "objectkey";
/// The operation param type of an object name encoded whole, `/` as `%2F`
/// (GCS). Such an operation is named-only.
pub const OBJECT_NAME: &str = "objectname";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub id: String,
    pub version: u32,
    pub title: String,
    /// `https://...`; empty (absent) for `transport = "mail"`.
    #[serde(default)]
    pub base_url: String,
    /// Literal hosts and `*.suffix` globs, or whole-host placeholders
    /// `{param}` (decision 1), or hosts with a placeholder inside one label
    /// (`s3.{region}.amazonaws.com`, plan 15).
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

/// How the connector reaches its upstream: HTTPS, or `mail` (SMTP send and
/// read-only IMAP, [`crate::mail`]).
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
    /// `aws_sigv4` only (required): the SigV4 service name (`s3`, `sts`).
    #[serde(default)]
    pub service: Option<String>,
    /// `gcp_sa` and `azure_sp` only (required): the OAuth scope, an
    /// `https://` URL.
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub id: String,
    pub capability: String,
    #[serde(default)]
    pub qualifier: Option<String>,
    pub kind: OpKind,
    /// Empty (absent) for a mail operation.
    #[serde(default)]
    pub method: String,
    /// Empty (absent) for a mail operation.
    #[serde(default)]
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
    /// Headers of this operation, with the syntax and banned names of
    /// [`Manifest::headers`]; they win over the manifest's and the agent's.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Query parameters with a fixed value, appended after the agent's. A
    /// named call may not set one; a proxied query may only repeat the
    /// exact value.
    #[serde(default)]
    pub fixed_query: BTreeMap<String, String>,
    /// The cloud IAM action of the operation (`s3:GetObject`), for the STS
    /// session policy.
    #[serde(default)]
    pub iam_action: Option<String>,
}

impl Operation {
    /// The body is built from `body_params`, `body_const` and `graphql`.
    pub fn builds_body(&self) -> bool {
        !self.body_params.is_empty() || !self.body_const.is_empty() || self.graphql.is_some()
    }

    /// Some path, query or body param of the operation has type `ty`.
    pub fn has_param_type(&self, ty: &str) -> bool {
        self.path_params
            .values()
            .chain(self.query.values())
            .chain(self.body_params.values())
            .any(|t| t == ty)
    }

    /// A proxied path can reach the operation: not a GraphQL one (its fixed
    /// document is the body) and none with an `objectname` (its `/` is
    /// encoded, which no raw path segment may carry).
    pub fn proxy_reachable(&self) -> bool {
        self.graphql.is_none() && !self.has_param_type(OBJECT_NAME)
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

/// An `x-amz-*` header name (any case). A SigV4 manifest may neither list
/// one in `request_headers` nor set one as a fixed header: the signer sets
/// its own ([`SIGV4_HEADERS`]), and every other one can change what a signed
/// call does (`x-amz-copy-source` turns a PUT into a copy, `x-amz-target`
/// picks a JSON-protocol action, ...).
fn is_amz_header(name: &str) -> bool {
    name.len() >= 6 && name.as_bytes()[..6].eq_ignore_ascii_case(b"x-amz-")
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
        for (name, spec) in &self.params {
            spec.param_type()
                .map_err(|e| bad(id, format!("param {name}: {e}")))?;
            if spec.ty == OBJECT_KEY || spec.ty == OBJECT_NAME {
                return Err(bad(
                    id,
                    format!("param {name}: {} is for operation params only", spec.ty),
                ));
            }
        }
        let mail = self.transport == Transport::Mail;
        if mail {
            // No base_url, the two host params, basic auth, the mail ops.
            crate::mail::check_manifest(self).map_err(|e| bad(id, e))?;
        } else {
            if !self.base_url.starts_with("https://") {
                return Err(bad(id, "base_url must be https://"));
            }
            for var in braces(&self.base_url).map_err(|e| bad(id, e))? {
                if !self.params.contains_key(var) {
                    return Err(bad(id, format!("base_url uses undeclared param {var}")));
                }
            }
        }
        self.check_hosts().map_err(|e| bad(id, e))?;
        for a in &self.auth {
            check_auth(a).map_err(|e| bad(id, e))?;
        }
        self.check_headers(&self.headers).map_err(|e| bad(id, e))?;
        // A SigV4 connector lists no `x-amz-*` request header: the signer
        // owns its own, and the others change what a signed call does
        // (`x-amz-copy-source`, `x-amz-acl`, `x-amz-target`, ...), which
        // policy never sees. No exception: no built-in needs one.
        if self.signs_sigv4() {
            if let Some(h) = self.request_headers.iter().find(|h| is_amz_header(h)) {
                return Err(bad(
                    id,
                    format!(
                        "request_headers: {h}: no x-amz-* header may be listed for a SigV4 connector"
                    ),
                ));
            }
        }
        let mut seen = BTreeSet::new();
        let mut shapes = BTreeSet::new();
        for op in &self.operation {
            // A GraphQL or `objectname` operation is named-only (never
            // matched by path), so several may share one endpoint.
            // A mail operation has no path at all.
            let segs = if !mail && op.proxy_reachable() {
                template_segments(&op.path).ok()
            } else {
                None
            };
            if let Some(segs) = segs {
                // The fixed query tells sub-resources apart (S3's
                // `GET /{key}?acl` next to GetObject); the proxy picks the
                // operation whose fixed names the query carries.
                if !shapes.insert((op.method.clone(), shape(&segs), op.fixed_query.clone())) {
                    return Err(bad(
                        id,
                        format!(
                            "operation {}: same method, path shape and fixed query as another",
                            op.id
                        ),
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
        let mail = self.transport == Transport::Mail;
        if !mail && !METHODS.contains(&op.method.as_str()) {
            return Err(format!(
                "method {:?} is not one of {}",
                op.method,
                METHODS.join(", ")
            ));
        }
        // A mail operation has no method or path (checked in `mail`).
        let vars: BTreeSet<&str> = if mail {
            BTreeSet::new()
        } else {
            template_segments(&op.path)?
                .into_iter()
                .filter_map(|s| match s {
                    Seg::Var { name, .. } => Some(name),
                    Seg::Lit(_) => None,
                })
                .collect()
        };
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
        if !mail {
            check_object_params(op)?;
        }
        self.check_headers(&op.headers)?;
        for (k, v) in &op.fixed_query {
            if k.is_empty()
                || !k
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
            {
                return Err(format!(
                    "fixed_query {k:?}: a name must be [A-Za-z0-9._~-]+"
                ));
            }
            if !v.bytes().all(|b| (0x20..0x7f).contains(&b)) {
                return Err(format!(
                    "fixed_query {k}: the value must be printable ASCII"
                ));
            }
            if declared.contains(k.as_str())
                || op.query.contains_key(k)
                || op.body_params.contains_key(k)
            {
                return Err(format!("fixed_query {k} is also a param of the operation"));
            }
        }
        if let Some(a) = &op.iam_action {
            let ok = (1..=128).contains(&a.len())
                && a.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".:/*-".contains(&b));
            if !ok {
                return Err("iam_action must match [A-Za-z0-9.:/*-]{1,128}".into());
            }
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
            if b == "raw" && self.transport == Transport::Mail {
                return Err("body = \"raw\" is not for transport = \"mail\"".into());
            }
            // A raw body is never parsed, so no amount can be read from it:
            // a cap on it would bind nothing.
            if b == "raw" && op.amount.is_some() {
                return Err("an amount needs a body the broker parses, not body = \"raw\"".into());
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

    /// Every service param that is a whole host: `{param}` entries of
    /// `hosts` (for mail, `smtp_host` and `imap_host`). Each value must be
    /// a bare hostname.
    pub fn host_params(&self) -> Vec<&str> {
        self.hosts
            .iter()
            .filter_map(|h| whole_placeholder(h))
            .collect()
    }

    /// Every service param that fills a placeholder inside one label of a
    /// host: of a `hosts` entry (`s3.{region}.amazonaws.com`) or of the base
    /// URL host (`{shop}.myshopify.com`). Each value must be one DNS label.
    pub fn label_host_params(&self) -> Vec<&str> {
        let mut out: Vec<&str> = self
            .hosts
            .iter()
            .map(String::as_str)
            .chain(self.base_host_template())
            .filter(|h| whole_placeholder(h).is_none())
            .filter_map(|h| label_placeholder(h).ok().flatten().map(|l| l.name))
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Decision 1: either fixed hosts and globs, or whole-host `{param}`
    /// entries, each a required param with an anchored pattern, one of which
    /// is exactly the base URL host. Plan 15 adds in-label placeholders
    /// (`s3.{region}.amazonaws.com`), next to fixed hosts and globs: the
    /// same param rules, and the value is one DNS label.
    fn check_hosts(&self) -> Result<(), String> {
        let placeholders: Vec<&str> = self
            .hosts
            .iter()
            .filter_map(|h| whole_placeholder(h))
            .collect();
        let mut in_label = Vec::new();
        for h in self.hosts.iter().filter(|h| whole_placeholder(h).is_none()) {
            if let Some(l) = label_placeholder(h).map_err(|e| format!("host {h:?}: {e}"))? {
                in_label.push(l.name);
            }
        }
        // The base URL host, when it is not a whole placeholder.
        if let Some(h) = self
            .base_host_template()
            .filter(|h| whole_placeholder(h).is_none())
        {
            if let Some(l) = label_placeholder(h).map_err(|e| format!("base_url host: {e}"))? {
                in_label.push(l.name);
            }
        }
        for p in placeholders.iter().chain(&in_label) {
            self.host_param_ok(p)?;
        }
        if placeholders.is_empty() {
            return Ok(());
        }
        if placeholders.len() != self.hosts.len() {
            return Err("hosts may not mix {param} entries with fixed hosts".into());
        }
        // A mail manifest has no base_url; its hosts are the SMTP and IMAP
        // host params (checked in `mail`).
        if self.transport == Transport::Mail {
            return Ok(());
        }
        match self.whole_host_param() {
            Some(p) if placeholders.contains(&p) => Ok(()),
            _ => Err("with {param} hosts, the base_url host must be exactly one of them".into()),
        }
    }

    /// The manifest authenticates with `aws_sigv4`.
    pub fn signs_sigv4(&self) -> bool {
        self.auth.iter().any(|a| a.kind == "aws_sigv4")
    }

    /// A host placeholder's param: declared, required, with an anchored
    /// pattern.
    fn host_param_ok(&self, p: &str) -> Result<(), String> {
        let spec = self
            .params
            .get(p)
            .ok_or_else(|| format!("host placeholder {{{p}}} is not a declared param"))?;
        if !spec.required {
            return Err(format!("host param {p} must be required"));
        }
        match spec.pattern.as_deref() {
            Some(pat) if pat.starts_with('^') && pat.ends_with('$') => Ok(()),
            _ => Err(format!(
                "host param {p} needs an anchored hostname pattern (^...$)"
            )),
        }
    }

    /// Fixed headers (the manifest's or an operation's): valid names the
    /// broker does not own, printable ASCII values, and placeholders that
    /// are required params.
    fn check_headers(&self, headers: &BTreeMap<String, String>) -> Result<(), String> {
        let auth_names: Vec<String> = self
            .auth
            .iter()
            .map(|a| match a.kind.as_str() {
                "header" => a.name.as_deref().unwrap_or("").to_ascii_lowercase(),
                _ => "authorization".to_string(),
            })
            .collect();
        let sigv4 = self.signs_sigv4();
        for (name, value) in headers {
            let h = http::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| format!("header {name:?}: not a valid header name"))?;
            let lower = h.as_str();
            if crate::request::ALWAYS_DROPPED.contains(&lower)
                || auth_names.iter().any(|a| a == lower)
                || (sigv4 && SIGV4_HEADERS.contains(&lower))
            {
                return Err(format!(
                    "header {name}: set by the broker, not the manifest"
                ));
            }
            // As for `request_headers`: a fixed `x-amz-*` header would be
            // signed into every call and can change what it does.
            if sigv4 && is_amz_header(lower) {
                return Err(format!(
                    "header {name}: no x-amz-* header may be set by a SigV4 connector"
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
    let cloud = CLOUD_AUTH_KINDS.contains(&a.kind.as_str());
    if cloud && !a.secret_field.is_empty() {
        return Err(format!("auth kind {} takes no secret_field", a.kind));
    }
    if !cloud && !matches!(a.kind.as_str(), "basic" | "oauth2") && a.secret_field.is_empty() {
        return Err("auth needs a secret_field".into());
    }
    match (&a.service, a.kind == "aws_sigv4") {
        (Some(_), false) => return Err("auth service is only for kind aws_sigv4".into()),
        (None, true) => return Err("auth kind aws_sigv4 needs a service".into()),
        (Some(s), true) => {
            let ok = (1..=64).contains(&s.len())
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
            if !ok {
                return Err("auth service must match [a-z0-9-]{1,64}".into());
            }
        }
        (None, false) => {}
    }
    let scoped = matches!(a.kind.as_str(), "gcp_sa" | "azure_sp");
    match (&a.scope, scoped) {
        (Some(_), false) => return Err("auth scope is only for kinds gcp_sa and azure_sp".into()),
        (None, true) => return Err(format!("auth kind {} needs a scope", a.kind)),
        (Some(s), true) => {
            let ok = s.len() <= 512
                && s.strip_prefix("https://").is_some_and(|r| {
                    !r.is_empty()
                        && !r.starts_with('/')
                        && r.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-._~:/".contains(&b))
                });
            if !ok {
                return Err("auth scope must be a plain https:// URL".into());
            }
        }
        (None, false) => {}
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
    param_name(name).then_some(name)
}

fn param_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// A lower-case LDH run: letters, digits and `-` (possibly empty).
fn ldh(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// One DNS label as a host param fills it: 1 to 63 lower-case letters,
/// digits and `-`, not starting or ending in `-`. No dot, so the value can
/// never add a label, and no `:`, `@`, `/` or `%`.
pub fn dns_label(v: &str) -> bool {
    (1..=63).contains(&v.len()) && ldh(v) && !v.starts_with('-') && !v.ends_with('-')
}

/// A host template with a placeholder inside one label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LabelHost<'a> {
    /// The labels before the placeholder label, with their trailing dot,
    /// and the placeholder label's fixed prefix.
    pub before: &'a str,
    pub name: &'a str,
    /// The placeholder label's fixed suffix and the labels after it.
    pub after: &'a str,
}

impl LabelHost<'_> {
    /// The host with `value` (one DNS label) in place of the placeholder.
    pub fn fill(&self, value: &str) -> String {
        format!("{}{value}{}", self.before, self.after)
    }
}

/// `None` for a host without braces; otherwise the in-label placeholder of
/// `h`, or why `h` is not one: exactly one `{name}` in one label (with an
/// optional lower-case LDH prefix and suffix in that label), every other
/// label lower-case LDH, and at least two fixed labels after it. That
/// keeps the value off a plain `example.com` domain, but it is a heuristic:
/// a multi-label public suffix (`co.uk`) is not detected. Manifests are
/// admin-controlled, so this guards against mistakes, not a hostile author.
pub(crate) fn label_placeholder(h: &str) -> Result<Option<LabelHost<'_>>, String> {
    if !h.contains(['{', '}']) {
        return Ok(None);
    }
    let open = h.find('{').ok_or("unbalanced }")?;
    let close = h[open..].find('}').ok_or("unbalanced {")? + open;
    let (before, name, after) = (&h[..open], &h[open + 1..close], &h[close + 1..]);
    if !param_name(name) {
        return Err(format!("{{{name}}} is not a param name"));
    }
    if before.contains(['{', '}']) || after.contains(['{', '}']) {
        return Err("a host holds at most one placeholder".into());
    }
    let (pre_labels, prefix): (Vec<&str>, &str) = match before.rsplit_once('.') {
        Some((ls, p)) => (ls.split('.').collect(), p),
        None => (Vec::new(), before),
    };
    let (suffix, post_labels): (&str, Vec<&str>) = match after.split_once('.') {
        Some((s, ls)) => (s, ls.split('.').collect()),
        None => (after, Vec::new()),
    };
    if !ldh(prefix) || !ldh(suffix) || pre_labels.iter().chain(&post_labels).any(|l| !dns_label(l))
    {
        return Err("the other labels must be lower-case letters, digits and -".into());
    }
    if post_labels.len() < 2 {
        return Err("the placeholder needs at least two fixed labels after it".into());
    }
    Ok(Some(LabelHost {
        before,
        name,
        after,
    }))
}

/// Decision 5: an `objectkey` is only the last whole path segment; an
/// `objectname` is a whole path segment or a query param. Neither goes in
/// a body.
fn check_object_params(op: &Operation) -> Result<(), String> {
    let segs = template_segments(&op.path)?;
    let last = segs.len().saturating_sub(1);
    for (i, s) in segs.iter().enumerate() {
        let Seg::Var {
            prefix,
            name,
            suffix,
        } = s
        else {
            continue;
        };
        let ty = op.path_params.get(*name).map(String::as_str);
        let whole = prefix.is_empty() && suffix.is_empty();
        if ty == Some(OBJECT_KEY) && !(whole && i == last) {
            return Err(format!(
                "path param {name}: an objectkey must be the last whole path segment"
            ));
        }
        if ty == Some(OBJECT_NAME) && !whole {
            return Err(format!(
                "path param {name}: an objectname must be a whole path segment"
            ));
        }
    }
    if op.query.values().any(|t| t == OBJECT_KEY) {
        return Err("an objectkey is a path param only".into());
    }
    if op
        .body_params
        .values()
        .any(|t| t == OBJECT_KEY || t == OBJECT_NAME)
    {
        return Err("objectkey and objectname are not body params".into());
    }
    // An object value holds `/`, so in the qualifier it could pose as the
    // placeholders after it (`{key}` = `x/other-bucket`): it must be the
    // last one.
    if let Some(q) = op.qualifier.as_deref() {
        let vars = braces(q)?;
        let is_object = |v: &str| {
            op.path_params
                .get(v)
                .or_else(|| op.query.get(v))
                .is_some_and(|t| t == OBJECT_KEY || t == OBJECT_NAME)
        };
        if let Some(i) = vars.iter().position(|v| is_object(v)) {
            if i + 1 != vars.len() {
                return Err(format!(
                    "qualifier: object param {} must be the last placeholder",
                    vars[i]
                ));
            }
        }
    }
    Ok(())
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
            service: None,
            scope: None,
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
            headers: BTreeMap::new(),
            fixed_query: BTreeMap::new(),
            iam_action: None,
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
