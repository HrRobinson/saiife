//! `mcp.list` and `mcp.call` (plan 17, Task 7): the gateway pipeline for
//! the tools of third-party MCP servers the daemon runs (decision 9). It
//! mirrors `api_ops::execute`: every call runs under the policy snapshot
//! taken when it starts, and writes one `connector` record (decision 10)
//! before it answers; an unrecorded result is withheld.
//!
//! The steps of a call:
//! 1. identify (`api_ops::identify`); 2. the disk gate; 3. lockdown;
//! 4. scope: it must list `mcp:<name>` (`no_scope`);
//! 5. resolve: the tool must be in the server's current `tools/list`,
//!    compared byte for byte (`unknown_operation`);
//! 6. validate: the arguments are the JSON text of an object, at most
//!    256 KiB, parsed refusing duplicate keys (`bad_param`);
//! 7. decide: [`decide_tool`] with the project overlay (it only tightens:
//!    its `allow` counts only outside locked mode);
//! 8. limits: the limiter key `(uid, "mcp:<name>", session)`, kind `read`
//!    for a tool that matches `read_tools`, else `write`;
//! 9. ask: an approval request of type `mcp`;
//! 10. send `tools/call` through the [`ToolCaller`];
//! 11. mask every string of the result with the server's secret values and
//!     the v1 patterns, then cut it at `max_response_bytes`;
//! 12. record; 13. return.
//!
//! `via` is what the client says (attribution only, never a decision).

use crate::api_ops::{self, Caller, Groups, Identity, Refused, LOW_DISK};
use crate::mcp_gateway::ToolCaller;
use crate::ops::{Ctx, GatewayPolicy, Notice, VERSION};
use saiife_audit::{DecisionKind, NewRecord, Record};
use saiife_broker::limits::{Key, Limiter};
use saiife_broker::manifest::OpKind;
use saiife_broker::mask::Masker;
use saiife_broker::pipeline::{
    cut_display, deny_reason, Outcome, PolicySnapshot, Via, MASKED_CONTENT_RULE, READ_SLACK,
};
use saiife_ipc::frame::MAX_ANSWER_FRAME;
use saiife_ipc::msg::{err, ok, ErrorCode, Request, OP_MCP_LIST};
use saiife_ipc::peer::PeerCred;
use saiife_policy::decide::Verdict;
use saiife_policy::{
    decide_tool, scope_for, tool_kind, valid_server_name, Mode, PolicyError, ServiceOverlay,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;
use time::OffsetDateTime;

/// The largest arguments text a call takes (decision 9, step 6).
pub const MAX_ARGUMENTS: usize = 256 * 1024;
/// The masked arguments an approval request shows, at most (then cut).
pub const DISPLAY_MAX: usize = 4096;
/// Each record param, at most (decision 10), after masking.
pub const PARAM_MAX: usize = 1024;
/// A tool name longer than this is a bad request (the supervisor keeps no
/// tool with a name over 128 bytes, so it could name none).
const MAX_TOOL: usize = 1024;
/// At most this many `overlays` in `mcp.list`.
const MAX_OVERLAYS: usize = 64;
/// What a cut result keeps free for its closing note.
const CUT_RESERVE: usize = 256;

pub async fn handle(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    match req.op.as_str() {
        OP_MCP_LIST => list(ctx, peer, req).await,
        _ => call(ctx, peer, req).await,
    }
}

// ------------------------------------------------------------ types

/// One `mcp.call` after step 1.
pub struct McpCall {
    pub uid: u32,
    pub user: String,
    pub session: Option<String>,
    pub project: String,
    pub server: String,
    /// As the client sent it; compared byte for byte with the listed names.
    pub tool: String,
    /// The JSON text of the arguments object, as the client sent it.
    pub arguments: Vec<u8>,
    pub overlay: Option<ServiceOverlay>,
    pub via: Via,
}

/// Argument values can hold anything: `Debug` shows sizes only.
impl std::fmt::Debug for McpCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpCall")
            .field("uid", &self.uid)
            .field("server", &self.server)
            .field("tool_len", &self.tool.len())
            .field("arguments_len", &self.arguments.len())
            .field("via", &self.via)
            .finish()
    }
}

/// The exact call kept while it waits for approval, sealed like
/// `StoredCall` (spec §8.10 `request_sealed`): what step 6 validated, as
/// canonical JSON bytes. After approval only this is sent.
#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredMcpCall {
    pub uid: u32,
    pub user: String,
    pub session: Option<String>,
    pub project: String,
    pub server: String,
    /// The tool exactly as listed.
    pub tool: String,
    /// The canonical JSON of the arguments object (base64 in the file).
    #[serde(with = "b64")]
    pub arguments: Vec<u8>,
    /// SHA-256 (hex) of `arguments`: what the approver was shown the hash
    /// of. At send the arguments about to go out must hash to it.
    pub arguments_sha256: String,
    /// The project's tightening overlay, applied again at send.
    pub overlay: Option<ServiceOverlay>,
    /// How the call came in (`mcp` or `cli`).
    pub via: String,
    /// The environment of the snapshot it was asked under (as
    /// `StoredCall::env`); the send refuses another (`env_changed`).
    pub env: Option<String>,
    /// Always true for an mcp request (`StoredCall::env_recorded`).
    pub env_recorded: bool,
}

impl std::fmt::Debug for StoredMcpCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredMcpCall")
            .field("uid", &self.uid)
            .field("server", &self.server)
            .field("arguments_len", &self.arguments.len())
            .finish()
    }
}

impl StoredMcpCall {
    /// The call [`send_approved`] runs, `via = approval`.
    pub fn call(&self) -> McpCall {
        McpCall {
            uid: self.uid,
            user: self.user.clone(),
            session: self.session.clone(),
            project: self.project.clone(),
            server: self.server.clone(),
            tool: self.tool.clone(),
            arguments: self.arguments.clone(),
            overlay: self.overlay.clone(),
            via: Via::Approval,
        }
    }
}

mod b64 {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)
    }
}

/// What step 9 hands the approval store: the exact call (to seal) and the
/// display copy, masked with the server's secret values and the v1
/// patterns.
#[derive(Debug, Clone)]
pub struct PendingMcp {
    pub stored: StoredMcpCall,
    /// Masked.
    pub tool: String,
    /// Masked.
    pub project: String,
    /// The arguments' canonical JSON, masked (and shown only when masking
    /// changed nothing), cut at [`DISPLAY_MAX`].
    pub display: String,
    /// `display` was cut: approving needs `ack_truncated`.
    pub truncated: bool,
}

/// How a call ended.
#[derive(Debug, Clone)]
pub enum McpOutcome {
    /// The server answered: the masked `CallToolResult`, cut.
    Done {
        result: Value,
        is_error: bool,
        truncated: bool,
    },
    Denied {
        rule: String,
    },
    Limited {
        limit: &'static str,
    },
    UpstreamFailed {
        reason: String,
    },
    /// Waits for approval as `id`; nothing was sent or counted.
    Pending {
        id: u64,
    },
}

/// What the pipeline learned about a call, for its record.
#[derive(Debug, Clone, Default)]
pub struct McpTrace {
    /// The tool, masked.
    pub tool: String,
    /// `read` or `write`, once the tool resolved.
    pub op_kind: Option<OpKind>,
    pub env: Option<String>,
    /// The server's secret names, joined by `,`.
    pub secret: Option<String>,
    /// The top-level arguments, masked, each at most [`PARAM_MAX`].
    pub params: BTreeMap<String, String>,
    /// Of the canonical arguments (the bytes sent).
    pub body_sha256: Option<String>,
    pub body_bytes: usize,
    /// Masked.
    pub project: String,
    pub resp_bytes: Option<usize>,
    pub is_error: Option<bool>,
    pub duration_ms: u64,
    /// `tools/call` was sent (it counts against the limits).
    pub sent: bool,
}

/// A new call, or one approved earlier (with the hash its approver saw).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage<'a> {
    New,
    Approved { sha256: Option<&'a str> },
}

// ------------------------------------------------------------ parsing

fn bad(id: u64, m: &str) -> Value {
    err(id, ErrorCode::BadRequest, m)
}

/// The arguments of `mcp.call`, checked. Errors never quote a value.
pub(crate) fn parse_call(args: &Map<String, Value>) -> Result<McpCall, &'static str> {
    let server = args
        .get("server")
        .and_then(Value::as_str)
        .filter(|s| valid_server_name(s))
        .ok_or("mcp.call takes a valid server name")?
        .to_string();
    let tool = match args.get("tool") {
        Some(Value::String(s)) if !s.is_empty() && s.len() <= MAX_TOOL => s.clone(),
        _ => return Err("mcp.call takes a tool name"),
    };
    // A string, not an object: the frame's parser keeps the last of two
    // equal keys, so only the text can be checked for them (step 6).
    let arguments = match args.get("arguments") {
        None | Some(Value::Null) => b"{}".to_vec(),
        Some(Value::String(s)) => s.as_bytes().to_vec(),
        Some(_) => return Err("arguments must be the JSON text of an object (a string)"),
    };
    let overlay = api_ops::parse_overlay(args.get("overlay"))?;
    let project = match args.get("project") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s))
            if s.len() <= api_ops::MAX_PROJECT && !s.contains(['\n', '\r', '\0']) =>
        {
            s.clone()
        }
        Some(_) => return Err("project must be a path"),
    };
    let via = match args.get("via") {
        None | Some(Value::Null) => Via::Mcp,
        Some(Value::String(s)) if s == "mcp" => Via::Mcp,
        Some(Value::String(s)) if s == "cli" => Via::Cli,
        Some(_) => return Err("via must be mcp or cli"),
    };
    Ok(McpCall {
        uid: 0,
        user: String::new(),
        session: None,
        project,
        server,
        tool,
        arguments,
        overlay,
        via,
    })
}

/// `mcp.list`'s `overlays`: keys `mcp:<name>`, at most [`MAX_OVERLAYS`].
fn parse_overlays(v: Option<&Value>) -> Result<BTreeMap<String, ServiceOverlay>, &'static str> {
    let Some(v) = v.filter(|v| !v.is_null()) else {
        return Ok(BTreeMap::new());
    };
    let m: BTreeMap<String, ServiceOverlay> = serde_json::from_value(v.clone())
        .map_err(|_| "overlays must map mcp:<server> to {allow, ask, deny}")?;
    if m.len() > MAX_OVERLAYS {
        return Err("overlays: too many servers");
    }
    let mut out = BTreeMap::new();
    for (k, o) in m {
        let name = k
            .strip_prefix("mcp:")
            .filter(|n| valid_server_name(n))
            .ok_or("overlays: keys are mcp:<server>")?;
        api_ops::check_overlay(&o)?;
        out.insert(name.to_string(), o);
    }
    Ok(out)
}

/// Step 6: the arguments object, or `None` (`bad_param`): over
/// [`MAX_ARGUMENTS`], not JSON, a duplicate key anywhere, too deep, or not
/// an object.
pub fn parse_arguments(b: &[u8]) -> Option<Map<String, Value>> {
    if b.len() > MAX_ARGUMENTS {
        return None;
    }
    match saiife_mcp::codec::parse_strict(b)? {
        Value::Object(o) => Some(o),
        _ => None,
    }
}

// ------------------------------------------------------------ helpers

fn hex(b: &[u8]) -> String {
    api_ops::hex(b)
}

fn kind_str(k: OpKind) -> &'static str {
    match k {
        OpKind::Read => "read",
        _ => "write",
    }
}

/// The record params of `args` (decision 10): each top-level key and value
/// masked (a string as it is, anything else as compact JSON), then cut at
/// [`PARAM_MAX`].
fn record_params(args: &Map<String, Value>, masker: &Masker) -> BTreeMap<String, String> {
    args.iter()
        .map(|(k, v)| {
            let text = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            (
                cut_display(&masker.mask_text(k), PARAM_MAX).0,
                cut_display(&masker.mask_text(&text), PARAM_MAX).0,
            )
        })
        .collect()
}

/// The text the approver is shown, when it is exactly what will be sent:
/// `None` when the masker would change it (a secret value, or a v1
/// pattern), as for a connector body. The canonical text is checked, and so
/// is every string of `args` (keys too) as parsed: a secret holding `"`,
/// `\` or a control char is escaped in the text, where its raw form is not
/// found.
fn faithful(masker: &Masker, b: &[u8], args: &Map<String, Value>) -> Option<String> {
    if masker.mask_bytes(b) != b {
        return None;
    }
    let text = std::str::from_utf8(b).ok()?;
    if masker.mask_text(text) != text {
        return None;
    }
    fn unchanged(m: &Masker, v: &Value) -> bool {
        match v {
            Value::String(s) => m.mask_text(s) == *s,
            Value::Array(a) => a.iter().all(|x| unchanged(m, x)),
            Value::Object(o) => o
                .iter()
                .all(|(k, x)| m.mask_text(k) == *k && unchanged(m, x)),
            _ => true,
        }
    }
    args.iter()
        .all(|(k, v)| masker.mask_text(k) == *k && unchanged(masker, v))
        .then(|| text.to_string())
}

/// Whether every number in the JSON text `b` (already parsed, so valid)
/// keeps its meaning through the parser and canonical JSON: no exponent
/// form (`1e2` would become `100.0`) and no integer outside the i64/u64
/// range (it would become a float and lose digits). Decimals like `1.5`
/// are kept.
pub fn numbers_exact(b: &[u8]) -> bool {
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        if in_str {
            match c {
                b'\\' => i += 1,
                b'"' => in_str = false,
                _ => {}
            }
            i += 1;
            continue;
        }
        if c == b'"' {
            in_str = true;
            i += 1;
            continue;
        }
        if c == b'-' || c.is_ascii_digit() {
            let start = i;
            while i < b.len() && b"0123456789+-.eE".contains(&b[i]) {
                i += 1;
            }
            let tok = &b[start..i];
            if tok.iter().any(|&x| x == b'e' || x == b'E') {
                return false;
            }
            let t = std::str::from_utf8(tok).unwrap_or("");
            if !tok.contains(&b'.') {
                if t.parse::<i64>().is_err() && t.parse::<u64>().is_err() {
                    return false;
                }
            } else if !decimal_exact(t) {
                return false;
            }
            continue;
        }
        i += 1;
    }
    true
}

/// Whether the decimal `t` (`-?digits.digits`) survives the f64 round trip
/// with the same value: its digits, ignoring a leading zero run and trailing
/// fraction zeros, equal those of the shortest f64 text. `123456789012345.678`
/// does not (f64 prints `123456789012345.69`).
fn decimal_exact(t: &str) -> bool {
    fn norm(s: &str) -> Option<(bool, String, String)> {
        let (neg, s) = match s.strip_prefix('-') {
            Some(r) => (true, r),
            None => (false, s),
        };
        let (i, f) = s.split_once('.')?;
        let i = i.trim_start_matches('0');
        let f = f.trim_end_matches('0');
        Some((neg, i.to_string(), f.to_string()))
    }
    let Ok(x) = t.parse::<f64>() else {
        return false;
    };
    let Some(n) = serde_json::Number::from_f64(x) else {
        return false;
    };
    let shown = n.to_string();
    let Some(a) = norm(t) else {
        return false;
    };
    match norm(&shown) {
        // `-0.0` is zero whichever way it is signed.
        Some(b) => a == b || (a.1.is_empty() && a.2.is_empty() && b.1.is_empty() && b.2.is_empty()),
        // The shortest text has no point (`1e21`, `5`): compare as integer.
        None => a.2.is_empty() && a.1 == shown.trim_start_matches('-').trim_start_matches('0'),
    }
}

fn json_len(v: &Value) -> usize {
    serde_json::to_vec(v).map_or(usize::MAX, |b| b.len())
}

/// The longest prefix of `t` (on a char boundary) whose JSON string form is
/// at most `room` bytes.
fn cut_to(t: &str, room: usize) -> &str {
    let mut end = room.min(t.len());
    loop {
        while !t.is_char_boundary(end) {
            end -= 1;
        }
        let n = json_len(&Value::String(t[..end].to_string()));
        if n <= room || end == 0 {
            return &t[..end];
        }
        end = end.saturating_sub((n - room).max(1));
    }
}

/// Step 11's cut: the masked result whole when its JSON is at most `max`
/// bytes; otherwise its content items in order while they fit, the text
/// item that crosses the limit cut to what is left, the rest (and a
/// `structuredContent` that no longer fits) dropped, and a closing note.
/// Masking ran first, so a cut never leaves part of a secret.
pub fn cut_result(v: Value, max: usize) -> (Value, bool) {
    let size = json_len(&v);
    if size <= max {
        return (v, false);
    }
    let note = |max: usize, size: usize| {
        json!({"type": "text", "text": format!(
            "[saiife: the result was cut at max_response_bytes ({max} bytes); it was {size} bytes]"
        )})
    };
    let Value::Object(mut o) = v else {
        return (fit(json!({"content": [note(max, size)]}), max), true);
    };
    let budget = max.saturating_sub(CUT_RESERVE);
    let items = match o.remove("content") {
        Some(Value::Array(a)) => a,
        _ => Vec::new(),
    };
    let structured = o.remove("structuredContent");
    let mut out = Map::new();
    if let Some(e) = o.remove("isError") {
        out.insert("isError".into(), e);
    }
    let mut used = json_len(&Value::Object(out.clone())) + 16;
    let mut kept = Vec::new();
    for item in items {
        let n = json_len(&item) + 1;
        if used + n <= budget {
            used += n;
            kept.push(item);
            continue;
        }
        if item.get("type").and_then(Value::as_str) == Some("text") {
            if let Some(t) = item.get("text").and_then(Value::as_str) {
                // `{"type":"text","text":""}` and a comma.
                let room = budget.saturating_sub(used + 28);
                let part = cut_to(t, room);
                if !part.is_empty() {
                    let cut = json!({"type": "text", "text": part});
                    used += json_len(&cut) + 1;
                    kept.push(cut);
                }
            }
        }
        break;
    }
    if let Some(sc) = structured {
        if used + json_len(&sc) + 24 <= budget {
            out.insert("structuredContent".into(), sc);
        }
    }
    kept.push(note(max, size));
    out.insert("content".into(), Value::Array(kept));
    (fit(Value::Object(out), max), true)
}

/// A cut result never exceeds `max`: when even the note does not fit (a
/// `max_response_bytes` below [`CUT_RESERVE`]), the shorter `[saiife:
/// cut]`; below that, an empty `content` (14 bytes, the smallest result).
fn fit(v: Value, max: usize) -> Value {
    if json_len(&v) <= max {
        return v;
    }
    let short = json!({"content": [{"type": "text", "text": "[saiife: cut]"}]});
    if json_len(&short) <= max {
        return short;
    }
    json!({"content": []})
}

// ------------------------------------------------------------ pipeline

fn denied(rule: &str) -> McpOutcome {
    McpOutcome::Denied {
        rule: rule.to_string(),
    }
}

/// Steps 3–11 of `call` under `snap`, for the caller whose groups are
/// `groups`; with the trace its record needs.
async fn run_stage(
    ctx: &Arc<Ctx>,
    tools: &dyn ToolCaller,
    call: &McpCall,
    stage: Stage<'_>,
    snap: &PolicySnapshot,
    groups: &Groups,
    agent: &str,
) -> (McpOutcome, McpTrace) {
    let started = Instant::now();
    let mut tr = McpTrace::default();
    // Every value of the server's secrets (all their forms) and the v1
    // patterns: what a connector answer is masked with. The record's
    // params too, also for a denied call.
    let values = tools.secret_values(&call.server);
    let refs: Vec<&str> = values.iter().map(|v| v.as_str()).collect();
    let masker = Masker::new(&refs);
    drop(refs);
    drop(values);
    // The record's params, when the text parses (a refused one leaves
    // none: the policy never saw any).
    if let Some(args) = parse_arguments(&call.arguments) {
        tr.params = record_params(&args, &masker);
    }
    tr.body_bytes = call.arguments.len();
    tr.body_sha256 = Some(hex(&Sha256::digest(&call.arguments)));
    let outcome = steps(
        ctx, tools, call, stage, snap, groups, agent, &mut tr, &masker,
    )
    .await;
    tr.tool = masker.mask_text(&call.tool);
    tr.project = masker.mask_text(&call.project);
    tr.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    (outcome, tr)
}

#[allow(clippy::too_many_arguments)]
async fn steps(
    ctx: &Arc<Ctx>,
    tools: &dyn ToolCaller,
    call: &McpCall,
    stage: Stage<'_>,
    snap: &PolicySnapshot,
    groups: &Groups,
    agent: &str,
    tr: &mut McpTrace,
    masker: &Masker,
) -> McpOutcome {
    let config = &snap.config;
    // 3. Lockdown (either scope), read once here.
    if ctx.lockdown.get().is_some() {
        return denied("lockdown");
    }
    // An approved call the policy in force no longer lets through.
    let changed = |rule: &str| match stage {
        Stage::New => denied(rule),
        Stage::Approved { .. } => denied("policy_changed"),
    };
    // 4. Scope: it must list `mcp:<name>`.
    let scope = match scope_for(config, groups, &call.user) {
        Ok(Some(s)) => s,
        Ok(None) => return changed("no_scope"),
        Err(PolicyError::ScopeConflict { .. }) => return changed("scope_conflict"),
        Err(_) => return denied("policy_invalid"),
    };
    tr.env = snap.env.clone();
    let service = format!("mcp:{}", call.server);
    if !scope.services.contains(&service) {
        return changed("no_scope");
    }
    let Some(cfg) = config.mcp.get(&call.server) else {
        return changed("no_scope");
    };
    let mut names: Vec<&str> = cfg.env.values().map(String::as_str).collect();
    names.sort_unstable();
    names.dedup();
    tr.secret = (!names.is_empty()).then(|| names.join(","));

    // 5. Resolve: in the server's current list, byte for byte.
    let Some(listed) = tools.tools(&call.server) else {
        // Not running: nothing can be sent.
        return denied("upstream_unavailable");
    };
    let Some(tool) = listed.iter().find(|t| t.name == call.tool) else {
        return denied("unknown_operation");
    };
    let kind = match tool_kind(cfg, &tool.name) {
        "read" => OpKind::Read,
        _ => OpKind::Write,
    };
    tr.op_kind = Some(kind);

    // 6. Validate: a JSON object, at most 256 KiB, no duplicate key.
    let Some(args) = parse_arguments(&call.arguments) else {
        return denied("bad_param");
    };
    // A number the round trip would change is refused, not rewritten. The
    // stored canonical text of an approved call was checked at its ask
    // (canonical JSON may write a decimal in exponent form).
    if stage == Stage::New && !numbers_exact(&call.arguments) {
        return denied("bad_param");
    }
    let canonical = saiife_policy::canonical_json(&Value::Object(args.clone())).into_bytes();
    let sha = hex(&Sha256::digest(&canonical));
    tr.body_bytes = canonical.len();
    tr.body_sha256 = Some(sha.clone());
    // An approved call sends only the arguments whose hash its approver saw.
    if let Stage::Approved { sha256 } = stage {
        if sha256 != Some(sha.as_str()) || canonical != call.arguments {
            return denied("body_changed");
        }
    }

    // 7. Decide.
    let ask = match decide_tool(cfg, call.overlay.as_ref(), snap.mode, &tool.name) {
        Verdict::Deny { rule } => return changed(&rule),
        Verdict::Ask => stage == Stage::New,
        Verdict::Allow => false,
    };

    // 8. Limits.
    let key = Key {
        uid: call.uid,
        service: service.clone(),
        session: call.session.clone(),
    };
    let lim: &Limiter = &ctx.limiter;
    let now = OffsetDateTime::now_utc();
    if lim.unavailable(now) {
        return denied("limits_unavailable");
    }
    // 9. Ask: checked without reserving; the send counts it for real.
    if ask {
        if let Err(limit) = lim.would_allow(&key, kind, None, false, &cfg.limits, now) {
            return McpOutcome::Limited { limit };
        }
        // The approver must see what will be sent: the tool name and the
        // arguments, unmasked.
        if masker.mask_text(&tool.name) != tool.name {
            return denied(MASKED_CONTENT_RULE);
        }
        let Some(text) = faithful(masker, &canonical, &args) else {
            return denied(MASKED_CONTENT_RULE);
        };
        let (display, truncated) = cut_display(&text, DISPLAY_MAX);
        let pending = PendingMcp {
            stored: StoredMcpCall {
                uid: call.uid,
                user: call.user.clone(),
                session: call.session.clone(),
                project: call.project.clone(),
                server: call.server.clone(),
                tool: tool.name.clone(),
                arguments: canonical,
                arguments_sha256: sha,
                overlay: call.overlay.clone(),
                via: call.via.as_str().to_string(),
                env: snap.env.clone(),
                env_recorded: true,
            },
            tool: masker.mask_text(&tool.name),
            project: masker.mask_text(&call.project),
            display,
            truncated,
        };
        return match crate::approval_ops::create_mcp(ctx, &pending, agent).await {
            Ok(id) => McpOutcome::Pending { id },
            Err(rule) => McpOutcome::Denied { rule },
        };
    }
    let reservation = match lim.check_and_commit(&key, kind, None, false, &cfg.limits, now) {
        Ok(r) => r,
        Err(limit) => return McpOutcome::Limited { limit },
    };

    // 10. Send. What was sent counts, whatever came back.
    let max = cfg
        .limits
        .max_response_bytes
        .unwrap_or(config.gateway.max_response_bytes);
    let max = usize::try_from(max).unwrap_or(usize::MAX);
    // The canonical arguments are sent: the bytes the record hashes and an
    // approver was shown (they parse: they were just written).
    let send_args = saiife_mcp::codec::parse_strict(&canonical).unwrap_or(Value::Object(args));
    reservation.commit();
    tr.sent = true;
    let sent = tools
        .call(
            &call.server,
            &tool.name,
            send_args,
            cfg.timeout,
            max.saturating_add(READ_SLACK),
        )
        .await;
    let result = match sent {
        Ok(v) => v,
        Err(e) => {
            return McpOutcome::UpstreamFailed {
                reason: masker.mask_text(&e.to_string()),
            }
        }
    };
    // 11. Mask with the whole set (the supervisor masked with the server's
    // own already), then cut.
    let result = match crate::mcp_gateway::child::mask_result(result, masker) {
        Ok(v) => v,
        Err(e) => {
            return McpOutcome::UpstreamFailed {
                reason: masker.mask_text(&e.to_string()),
            }
        }
    };
    let (result, truncated) = cut_result(result, max);
    let is_error = result.get("isError") == Some(&Value::Bool(true));
    tr.is_error = Some(is_error);
    tr.resp_bytes = Some(json_len(&result));
    McpOutcome::Done {
        result,
        is_error,
        truncated,
    }
}

/// Send an approved mcp request (spec §6.10.1 step 4): the stored call,
/// re-run through steps 3–8 under the policy in force now (`snap`), then
/// sent. `shown_sha256` is the hash the approver was shown. Returns the
/// call (`via = approval`) for its record.
pub(crate) async fn send_approved(
    ctx: &Arc<Ctx>,
    tools: &dyn ToolCaller,
    stored: &StoredMcpCall,
    shown_sha256: Option<&str>,
    snap: &PolicySnapshot,
    groups: &Groups,
    agent: &str,
) -> (McpCall, McpOutcome, McpTrace) {
    let call = stored.call();
    if shown_sha256 != Some(stored.arguments_sha256.as_str()) {
        let tr = McpTrace {
            tool: Masker::new(&[]).mask_text(&call.tool),
            ..McpTrace::default()
        };
        return (call, denied("body_changed"), tr);
    }
    let stage = Stage::Approved {
        sha256: Some(stored.arguments_sha256.as_str()),
    };
    let (o, t) = run_stage(ctx, tools, &call, stage, snap, groups, agent).await;
    (call, o, t)
}

/// The `connector` record of an mcp call (decision 10): `tool = "mcp"`,
/// `service = "mcp:<name>"`, `operation` the tool (masked), no capability,
/// `op_kind`, the masked params, the hash and size of the canonical
/// arguments, `status = null`, `mcp_is_error`, `resp_bytes`, the server's
/// secret names and `via`. The caller sets `peer` (and the approval link).
pub fn mcp_record(
    call: &McpCall,
    snap: &PolicySnapshot,
    tr: &McpTrace,
    outcome: &McpOutcome,
    agent: &str,
    saiife_version: &str,
) -> Record {
    let service = format!("mcp:{}", call.server);
    let mut input = format!("{service} {}", tr.tool);
    for (k, v) in &tr.params {
        input.push_str(&format!(" {k}={v}"));
    }
    let (decision, rule, reason, limit) = match outcome {
        McpOutcome::Done { .. } => (DecisionKind::Allow, None, None, None),
        McpOutcome::Denied { rule } => (
            DecisionKind::Deny,
            Some(rule.clone()),
            deny_reason(rule).map(str::to_string),
            None,
        ),
        McpOutcome::Limited { limit } => (
            DecisionKind::Deny,
            None,
            Some(format!("limit reached: {limit}")),
            Some(*limit),
        ),
        McpOutcome::UpstreamFailed { reason } => (
            DecisionKind::Allow,
            None,
            Some(format!("upstream failed: {reason}")),
            None,
        ),
        McpOutcome::Pending { id } => (
            DecisionKind::Ask,
            None,
            Some(format!("waiting for approval #{id}")),
            None,
        ),
    };
    let project = if tr.project.is_empty() {
        Masker::new(&[]).mask_text(&call.project)
    } else {
        tr.project.clone()
    };
    let mut r = Record::new(
        NewRecord {
            agent,
            project: &project,
            session: call.session.as_deref(),
            tool: "mcp",
            input: &input,
            decision,
            pack: None,
            rule: rule.as_deref(),
            reason: reason.as_deref(),
            mode: match snap.mode {
                Mode::Locked => "locked",
                Mode::Developer => "developer",
            },
            policy: Some(&snap.hash),
            permission_mode: None,
        },
        saiife_version,
    );
    r.kind = Some("connector".into());
    r.uid = Some(call.uid);
    r.user = Some(call.user.clone());
    let e = &mut r.extra;
    e.insert("service".into(), service.into());
    e.insert("operation".into(), tr.tool.clone().into());
    e.insert("capability".into(), Value::Null);
    e.insert("env".into(), json!(tr.env));
    e.insert("params".into(), json!(tr.params));
    e.insert("body_sha256".into(), json!(tr.body_sha256));
    e.insert("body_bytes".into(), json!(tr.body_bytes));
    e.insert("status".into(), Value::Null);
    e.insert("mcp_is_error".into(), json!(tr.is_error.unwrap_or(false)));
    e.insert("resp_bytes".into(), json!(tr.resp_bytes));
    e.insert("duration_ms".into(), json!(tr.duration_ms));
    e.insert("secret".into(), json!(tr.secret));
    e.insert("limit".into(), json!(limit));
    e.insert("via".into(), call.via.as_str().into());
    if let McpOutcome::Pending { id } = outcome {
        e.insert("approval".into(), (*id).into());
    }
    e.insert("op_kind".into(), json!(tr.op_kind.map(kind_str)));
    e.insert("amount".into(), Value::Null);
    r
}

/// `mcp.call` from a client: steps 1–13 with the daemon's tool caller.
async fn call(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    let id = req.id;
    let call = match parse_call(&req.args) {
        Ok(c) => c,
        Err(m) => return bad(id, m),
    };
    let tools = Arc::clone(&ctx.tool_caller);
    match execute(ctx, tools.as_ref(), &Caller::Unix(*peer), call).await {
        Ok(outcome) => answer(id, outcome),
        Err(Refused::LowDisk(code)) => err(id, code, LOW_DISK),
        Err(Refused::Unrecorded(m)) => err(id, ErrorCode::Internal, &m),
    }
}

/// Steps 1–12 for a parsed call: identity from `caller` (whatever the
/// request put there), the policy in force when it starts, and its one
/// record, written before the outcome is returned.
pub(crate) async fn execute(
    ctx: &Arc<Ctx>,
    tools: &dyn ToolCaller,
    caller: &Caller,
    mut call: McpCall,
) -> Result<McpOutcome, Refused> {
    // A stop waits for this call (and its record) before it ends the log.
    let _busy = ctx.calls.enter();
    // 2. Disk gate: a call that cannot be recorded is not made.
    let uid = caller.uid();
    if let Err(code) = api_ops::disk_ok(ctx, uid) {
        ctx.notice(uid, Notice::LowDisk);
        return Err(Refused::LowDisk(code));
    }
    // 1. Identify.
    let mut who = Identity::default();
    api_ops::identify(ctx, caller, &mut who).await;
    call.uid = who.uid;
    call.user = who.user;
    call.session = who.session;
    let agent = who.agent;
    let groups = Groups(who.groups);

    let state = ctx.policy();
    let (outcome, trace, gw, env_name) = match &state.gateway {
        Some(g) => match g.select_env(api_ops::gateway_mode(ctx), &groups, &call.user, None) {
            Ok((env_name, _)) => {
                let snap = g.snapshot_for(env_name);
                let (o, t) = run_stage(ctx, tools, &call, Stage::New, snap, &groups, &agent).await;
                (o, t, Arc::clone(g), env_name.map(str::to_string))
            }
            Err(rule) => (denied(rule), McpTrace::default(), Arc::clone(g), None),
        },
        None => (
            denied("policy_invalid"),
            McpTrace::default(),
            Arc::new(GatewayPolicy {
                snap: api_ops::no_policy_snapshot(state.hash.clone(), ctx.mode),
                by_env: Default::default(),
                catalog: Default::default(),
            }),
            None,
        ),
    };
    let snap = gw.snapshot_for(env_name.as_deref());
    let mut trace = trace;
    if trace.tool.is_empty() {
        trace.tool = Masker::new(&[]).mask_text(&call.tool);
    }
    if let McpOutcome::Limited { limit } = &outcome {
        ctx.notify_limit(uid, &format!("mcp:{}", call.server), &trace.tool, limit);
    }
    // 12. Record, before the answer.
    let mut rec = mcp_record(&call, snap, &trace, &outcome, &agent, VERSION);
    if snap.hash.is_empty() {
        rec.policy = None;
    }
    rec.extra.insert("peer".into(), caller.record());
    if let Err(e) = ctx.writer.append(rec).await {
        return Err(Refused::Unrecorded(format!(
            "the connector record could not be written: {e}"
        )));
    }
    Ok(outcome)
}

/// The answer of an outcome, in `api.call`'s shapes: `{status: null,
/// result, truncated}`, `{pending}`, or `denied`, `limited`,
/// `upstream_failed`.
pub(crate) fn answer(id: u64, outcome: McpOutcome) -> Value {
    match outcome {
        McpOutcome::Done {
            result, truncated, ..
        } => {
            if json_len(&result) > MAX_ANSWER_FRAME - 1_048_576 {
                return err(
                    id,
                    ErrorCode::UpstreamFailed,
                    "the result is too large for the control socket; lower max_response_bytes",
                );
            }
            let mut m = Map::new();
            m.insert("status".into(), Value::Null);
            m.insert("result".into(), result);
            m.insert("truncated".into(), truncated.into());
            ok(id, m)
        }
        McpOutcome::Denied { rule } => api_ops::answer(id, Outcome::Denied { rule }),
        McpOutcome::Limited { limit } => api_ops::answer(id, Outcome::Limited { limit }),
        McpOutcome::UpstreamFailed { reason } => {
            api_ops::answer(id, Outcome::UpstreamFailed { reason })
        }
        McpOutcome::Pending { id: p } => api_ops::answer(id, Outcome::Pending { id: p }),
    }
}

// ------------------------------------------------------------ list

/// `mcp.list`: the tools of the running servers in the caller's scope whose
/// action (with the client's overlay for `mcp:<name>`) is `allow` or
/// `ask`, as the server listed them (names byte for byte, descriptions
/// cleaned and masked by the supervisor). Listing grants nothing: a call
/// is decided again under the policy in force then.
async fn list(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    let id = req.id;
    let overlays = match parse_overlays(req.args.get("overlays")) {
        Ok(o) => o,
        Err(m) => return bad(id, m),
    };
    let servers = servers_for(ctx, ctx.tool_caller.as_ref(), peer.uid, &overlays).await;
    let servers = Value::Array(servers);
    let tools_hash = format!(
        "sha256:{}",
        hex(&Sha256::digest(
            saiife_policy::canonical_json(&servers).as_bytes()
        ))
    );
    let mut m = Map::new();
    m.insert("servers".into(), servers);
    m.insert("tools_hash".into(), tools_hash.into());
    ok(id, m)
}

/// The servers of `uid`'s scope and their listed tools (see [`list`]).
pub(crate) async fn servers_for(
    ctx: &Arc<Ctx>,
    tools: &dyn ToolCaller,
    uid: u32,
    overlays: &BTreeMap<String, ServiceOverlay>,
) -> Vec<Value> {
    let mut out = Vec::new();
    let state = ctx.policy();
    let (Some(g), Some(user)) = (&state.gateway, ctx.name_of(uid).await) else {
        return out;
    };
    let groups = Groups(ctx.groups_of(&user).await);
    let Ok((env, _)) = g.select_env(api_ops::gateway_mode(ctx), &groups, &user, None) else {
        return out;
    };
    let snap = g.snapshot_for(env);
    let Ok(Some(scope)) = scope_for(&snap.config, &groups, &user) else {
        return out;
    };
    for entry in &scope.services {
        let Some(name) = entry.strip_prefix("mcp:") else {
            continue;
        };
        let (Some(cfg), Some(listed)) = (snap.config.mcp.get(name), tools.tools(name)) else {
            continue;
        };
        let mut items = Vec::new();
        for t in listed.iter() {
            let action = match decide_tool(cfg, overlays.get(name), snap.mode, &t.name) {
                Verdict::Allow => "allow",
                Verdict::Ask => "ask",
                Verdict::Deny { .. } => continue,
            };
            let mut o = Map::new();
            o.insert("name".into(), t.name.clone().into());
            if let Some(title) = &t.title {
                o.insert("title".into(), title.clone().into());
            }
            o.insert(
                "description".into(),
                t.description.clone().unwrap_or_default().into(),
            );
            o.insert("inputSchema".into(), t.input_schema.clone());
            o.insert("action".into(), action.into());
            items.push(Value::Object(o));
        }
        out.push(json!({"name": name, "tools": items}));
    }
    out
}

#[cfg(test)]
mod tests;
