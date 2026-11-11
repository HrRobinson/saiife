//! `link.sock` (plan 29, Task 4): the Workspace link's own socket and
//! dispatcher, and the execution of verified frames against the box source.
//!
//! `link.sock` answers [`LINK_OPS`] only; every other op name is
//! `unknown_op` before its args are read, so a MachineOnly op has no route
//! from link at all. A frame passes `Workspace::check` (signature, machine,
//! epoch, time, level, replay), then the peer must be the device owner's
//! uid, then [`execute`] maps its action to the [`saiife_wire::BoxSource`].
//!
//! Records (`kind = "workspace"`): each state-changing action and each
//! refusal after a valid signature. A frame that fails before its signature
//! verifies is never recorded (anyone who reaches the socket could flood the
//! log); it bumps `Workspace::refused_unsigned` instead (`status` shows it).
//! Successful reads are not recorded, nor a box source's error on a read.

use crate::ops::{Conn, Ctx};
use crate::workspace::SignPurpose;
use saiife_audit::{DecisionKind, Record};
use saiife_ipc::msg::{
    err, err_with, ok, ErrorCode, Request, LINK_OPS, OP_HELLO, OP_WORKSPACE_FRAME,
    OP_WORKSPACE_HELLO, OP_WORKSPACE_PAIR_FINISH, OP_WORKSPACE_SIGN,
};
use saiife_ipc::peer::comm;
use saiife_wire::device::DeviceState;
use saiife_wire::frame::{parse_body, SignedFrame, TouchProof};
use saiife_wire::level::{actions as a, spawn_level, Level};
use saiife_wire::pair::PairRequest;
use saiife_wire::seal::{machine_hello_msg, SealBinding};
use saiife_wire::source::{
    check_text, BoxError, BoxId, BoxSource, SpawnReq, Start, MAX_TASK_BYTES,
};
use saiife_wire::verify::Verified;
use saiife_wire::{b64, WireError};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::Arc;

/// How the frame reached link: the browser on this machine, or a sealed
/// hub session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Local,
    Hub,
}

impl Via {
    pub fn as_str(self) -> &'static str {
        match self {
            Via::Local => "local",
            Via::Hub => "hub",
        }
    }
}

/// A frame the daemon will not carry out: the answer's `error`, `rule` and
/// `message`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub code: ErrorCode,
    pub rule: &'static str,
    pub message: String,
}

impl Refused {
    fn new(code: ErrorCode, rule: &'static str, message: impl Into<String>) -> Refused {
        Refused {
            code,
            rule,
            message: message.into(),
        }
    }

    fn answer(&self, id: u64) -> Value {
        let mut m = Map::new();
        m.insert("rule".into(), self.rule.into());
        err_with(id, self.code, &self.message, m)
    }
}

/// Remote actions plan 31 fills in (touch-bound ones and their helpers).
/// Until then every one is refused: Touch ones `touch_required`, the Signed
/// ones `unavailable`.
pub const LATER: &[&str] = &[
    "box.land",
    "box.push",
    "box.pr",
    "box.steer",
    "box.revise",
    "box.resume",
    "approval.list",
    "approval.approve",
    "approval.reject",
    "workspace.touch.begin",
];

/// The Signed actions [`execute`] carries out (every other Signed entry of
/// `saiife_wire::level::REMOTE` is in [`LATER`]; a test keeps it so).
pub const HANDLED: &[&str] = &[
    a::WORKSPACE_WHOAMI,
    a::BOX_OVERVIEW,
    a::BOX_LIST,
    a::BOX_TEMPLATES,
    a::BOX_DIFF,
    a::BOX_TERM_READ,
    a::BOX_INBOX,
    a::BOX_STOP,
    a::BOX_PAUSE,
    a::BOX_DISCARD,
    a::BOX_REORDER,
    a::BOX_SPAWN,
    a::LOCKDOWN_ON,
];

/// The handled actions that change something: always recorded.
const CHANGES: &[&str] = &[
    a::BOX_STOP,
    a::BOX_PAUSE,
    a::BOX_DISCARD,
    a::BOX_REORDER,
    a::BOX_SPAWN,
    a::LOCKDOWN_ON,
];

/// The most box ids a `box.reorder` takes.
const MAX_REORDER: usize = 256;
/// The longest template name and repo display name a `box.spawn` takes.
const MAX_NAME_BYTES: usize = 256;
/// The hub-hello nonce, in bytes.
const HUB_NONCE: std::ops::RangeInclusive<usize> = 16..=64;

/// `link.sock`: `hello`, `workspace.hello`, `workspace.pair.finish`,
/// `workspace.frame` and `workspace.sign`. Any other op is `unknown_op`,
/// with nothing read and nothing recorded.
pub async fn dispatch_link(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value {
    if !LINK_OPS.contains(&req.op.as_str()) {
        return unknown(&req);
    }
    match req.op.as_str() {
        OP_HELLO => crate::ops::hello_in(req.id, ctx.mode.as_str()),
        OP_WORKSPACE_HELLO => hello(ctx, req),
        OP_WORKSPACE_PAIR_FINISH => pair_finish(ctx, conn, req).await,
        OP_WORKSPACE_FRAME => frame(ctx, conn, req).await,
        OP_WORKSPACE_SIGN => sign(ctx, conn, req).await,
        _ => unknown(&req),
    }
}

fn unknown(req: &Request) -> Value {
    err(
        req.id,
        ErrorCode::UnknownOp,
        &format!("unknown op {:?} on link.sock", req.op),
    )
}

fn locked() -> Refused {
    Refused::new(
        ErrorCode::Unavailable,
        "workspace_locked",
        "the Workspace is locked (see the daemon's start warning)",
    )
}

fn bad(message: impl Into<String>) -> Refused {
    Refused::new(ErrorCode::BadRequest, "bad_request", message)
}

/// The uid of the account `user`, by the daemon's own lookup.
async fn uid_of(ctx: &Arc<Ctx>, user: &str) -> Option<u32> {
    let dir = Arc::clone(&ctx.directory);
    let user = user.to_string();
    tokio::task::spawn_blocking(move || dir.user(&user).map(|u| u.uid))
        .await
        .ok()
        .flatten()
}

async fn append(ctx: &Arc<Ctx>, rec: Record) -> Result<(), String> {
    let r = ctx.writer.append(rec).await.map(|_| ());
    if let Err(e) = &r {
        eprintln!("saiifed: warning: cannot write workspace record: {e}");
    }
    r
}

/// A `workspace` record of `action`, with the link peer when there is one.
async fn base_record(ctx: &Arc<Ctx>, conn: Option<&Conn>, action: &str) -> Record {
    let mut rec = ctx.record("workspace", action);
    rec.extra.insert("action".into(), action.into());
    if let Some(conn) = conn {
        let peer = &conn.peer;
        rec.uid = Some(peer.uid);
        rec.sid = peer.sid.clone();
        rec.user = ctx.peer_name(peer).await;
        rec.extra.insert(
            "peer".into(),
            json!({"pid": peer.pid, "comm": comm(peer.pid)}),
        );
    }
    rec
}

/// A frame's record: `extra = {action, device, label, via, level}`.
async fn frame_record(
    ctx: &Arc<Ctx>,
    conn: Option<&Conn>,
    action: &str,
    device_id: &str,
    via: Via,
    level: Option<Level>,
) -> Record {
    let mut rec = base_record(ctx, conn, action).await;
    let label = ctx.workspace.device(device_id).map(|d| d.label);
    rec.extra.insert("device".into(), device_id.into());
    rec.extra.insert("label".into(), json!(label));
    rec.extra.insert("via".into(), via.as_str().into());
    // An action no table names: "unknown".
    rec.extra.insert(
        "level".into(),
        level.map_or_else(|| "unknown".into(), |l| json!(l)),
    );
    rec
}

fn deny(rec: &mut Record, r: &Refused) {
    rec.decision = DecisionKind::Deny;
    rec.rule = Some(r.rule.into());
    rec.reason = Some(r.message.clone());
}

/// `workspace.hello {}` -> `{machine_id, machine_pub, epoch, frame_version}`.
fn hello(ctx: &Arc<Ctx>, req: Request) -> Value {
    if ctx.workspace.locked() {
        return locked().answer(req.id);
    }
    let m = ctx
        .workspace
        .hello()
        .as_object()
        .cloned()
        .unwrap_or_default();
    ok(req.id, m)
}

/// `workspace.pair.finish {pair_id, device_pub, label, proof}` ->
/// `{device_id, short_code}`. No peer check: the offer's proof is the
/// authority. Records `pair_request`; a refused request is not recorded
/// (it proves nothing about who sent it).
async fn pair_finish(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value {
    let id = req.id;
    if ctx.workspace.locked() {
        return locked().answer(id);
    }
    let pr: PairRequest = match serde_json::from_value(Value::Object(req.args)) {
        Ok(p) => p,
        Err(e) => {
            return bad(format!(
                "workspace.pair.finish takes {{pair_id, device_pub, label, proof}}: {e}"
            ))
            .answer(id)
        }
    };
    let now = ctx.workspace.now();
    let (device, short_code) = match ctx.workspace.finish_pair(&pr, now) {
        Ok(x) => x,
        Err(e) => {
            let code = match &e {
                WireError::Malformed(_) => ErrorCode::BadRequest,
                WireError::PairFull => ErrorCode::Busy,
                WireError::Store(_) => ErrorCode::Unavailable,
                _ => ErrorCode::Forbidden,
            };
            return Refused::new(code, e.rule(), e.to_string()).answer(id);
        }
    };
    let mut rec = base_record(ctx, Some(conn), "pair_request").await;
    rec.extra.insert("device".into(), device.id.clone().into());
    rec.extra
        .insert("label".into(), device.label.clone().into());
    rec.extra.insert("pair_id".into(), pr.pair_id.into());
    if let Err(e) = append(ctx, rec).await {
        return err(
            id,
            ErrorCode::Unrecorded,
            &format!("the device waits for confirmation, but its record could not be written: {e}"),
        );
    }
    let mut m = Map::new();
    m.insert("device_id".into(), device.id.into());
    m.insert("short_code".into(), short_code.into());
    ok(id, m)
}

/// The args of `workspace.frame`: `{body, sig, touch?, via, channel_device?}`.
fn frame_args(args: &Map<String, Value>) -> Result<(SignedFrame, Via, Option<String>), String> {
    const KEYS: [&str; 5] = ["body", "sig", "touch", "via", "channel_device"];
    if let Some(k) = args.keys().find(|k| !KEYS.contains(&k.as_str())) {
        return Err(format!("workspace.frame does not take {k:?}"));
    }
    let s = |k: &str| match args.get(k) {
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(format!("workspace.frame takes {k}: a string")),
    };
    let body = s("body")?;
    let sig = s("sig")?;
    let touch = match args.get("touch") {
        None | Some(Value::Null) => None,
        Some(v) => Some(
            serde_json::from_value::<TouchProof>(v.clone())
                .map_err(|e| format!("touch is not a touch proof: {e}"))?,
        ),
    };
    let via = match args.get("via").and_then(Value::as_str) {
        Some("local") => Via::Local,
        Some("hub") => Via::Hub,
        _ => return Err("workspace.frame takes via: \"local\" or \"hub\"".into()),
    };
    let channel = match args.get("channel_device") {
        None | Some(Value::Null) => None,
        Some(Value::String(c)) => Some(c.clone()),
        Some(_) => return Err("channel_device is a string".into()),
    };
    match (via, &channel) {
        (Via::Hub, None) => Err("a hub frame takes channel_device".into()),
        (Via::Local, Some(_)) => Err("a local frame takes no channel_device".into()),
        _ => Ok((SignedFrame { body, sig, touch }, via, channel)),
    }
}

/// Whether `check` refused only after the frame's signature verified.
fn after_signature(e: &WireError) -> bool {
    matches!(
        e,
        WireError::DevicePending
            | WireError::WrongMachine
            | WireError::StaleEpoch
            | WireError::Expired
            | WireError::NotYetValid
            | WireError::UnknownAction(_)
            | WireError::MachineOnly(_)
            | WireError::Replayed
            | WireError::Busy
    )
}

fn check_refusal(e: &WireError) -> Refused {
    let code = match e {
        WireError::Malformed(_) => ErrorCode::BadRequest,
        WireError::Busy => ErrorCode::Busy,
        _ => ErrorCode::Forbidden,
    };
    Refused::new(code, e.rule(), e.to_string())
}

/// `workspace.frame` -> `{result}`.
async fn frame(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value {
    let id = req.id;
    let (sf, via, channel) = match frame_args(&req.args) {
        Ok(x) => x,
        Err(m) => {
            ctx.workspace.note_unsigned();
            return bad(m).answer(id);
        }
    };
    let now = ctx.workspace.now();
    let v = match ctx.workspace.check(&sf, now) {
        Ok(v) => v,
        Err(e) => {
            let r = check_refusal(&e);
            if after_signature(&e) {
                // The body parsed and its signature verified.
                if let Ok(f) = parse_body(sf.body.as_bytes()) {
                    let level = saiife_wire::level_for(&f.action);
                    let mut rec =
                        frame_record(ctx, Some(conn), &f.action, &f.device_id, via, level).await;
                    deny(&mut rec, &r);
                    let _ = append(ctx, rec).await;
                }
            } else {
                ctx.workspace.note_unsigned();
            }
            return r.answer(id);
        }
    };
    // The daemon answers a device's frames to its owner's processes only.
    let owner_uid = uid_of(ctx, &v.owner_user).await;
    let refused = if owner_uid != Some(conn.peer.uid) {
        Some(Refused::new(
            ErrorCode::Forbidden,
            "wrong_owner",
            "this device belongs to another user than the link process",
        ))
    } else if channel.as_ref().is_some_and(|c| *c != v.device_id) {
        Some(Refused::new(
            ErrorCode::Forbidden,
            "wrong_device",
            "the frame is signed by another device than the hub session's",
        ))
    } else {
        None
    };
    if let Some(r) = refused {
        let mut rec = frame_record(
            ctx,
            Some(conn),
            &v.frame.action,
            &v.device_id,
            via,
            Some(v.level),
        )
        .await;
        deny(&mut rec, &r);
        let _ = append(ctx, rec).await;
        return r.answer(id);
    }
    match run(ctx, &v, via, Some(conn)).await {
        Ok(result) => {
            let mut m = Map::new();
            m.insert("result".into(), result);
            ok(id, m)
        }
        Err(r) => r.answer(id),
    }
}

/// One verified frame -> the answer's `result`. Exposed for plan 30's
/// tests. The caller has run `Workspace::check` and checked the peer; this
/// refuses every Touch action (`touch_required`, also `box.spawn` with a
/// template that reaches secrets or the network: no touch proof is verified
/// before plan 31) and every name in [`LATER`], and records as the module
/// says. Records written through `execute` carry no peer (no `uid`, `user`
/// or `peer` field): it has no connection; `workspace.frame` on `link.sock`
/// records its peer.
pub async fn execute(ctx: &Arc<Ctx>, v: &Verified, via: Via) -> Result<Value, Refused> {
    run(ctx, v, via, None).await
}

/// Why an action failed: a refusal by the daemon (always recorded), or the
/// box source's error (recorded for a change only).
enum Fail {
    Policy(Refused),
    Source(Refused),
}

async fn run(
    ctx: &Arc<Ctx>,
    v: &Verified,
    via: Via,
    conn: Option<&Conn>,
) -> Result<Value, Refused> {
    let action = v.frame.action.as_str();
    let mut level = v.level;
    let out = act(ctx, v, &mut level).await;
    let changing = CHANGES.contains(&action);
    let (record, refused) = match &out {
        Ok(_) => (changing, None),
        Err(Fail::Policy(r)) => (true, Some(r)),
        Err(Fail::Source(r)) => (changing, Some(r)),
    };
    if record {
        let mut rec = frame_record(ctx, conn, action, &v.device_id, via, Some(level)).await;
        if let Some(b) = v.frame.args.get("id").and_then(Value::as_str) {
            if BoxId::parse(b).is_ok() {
                rec.extra.insert("box".into(), b.into());
            }
        }
        if let Some(r) = refused {
            deny(&mut rec, r);
        }
        if let Err(e) = append(ctx, rec).await {
            if refused.is_none() {
                return Err(Refused::new(
                    ErrorCode::Unrecorded,
                    "unrecorded",
                    format!("{action} was done, but its record could not be written: {e}"),
                ));
            }
        }
    }
    out.map_err(|f| match f {
        Fail::Policy(r) | Fail::Source(r) => r,
    })
}

fn invalid(message: impl Into<String>) -> Fail {
    Fail::Policy(Refused::new(ErrorCode::BadRequest, "invalid", message))
}

fn internal(e: impl std::fmt::Display) -> Fail {
    Fail::Source(Refused::new(ErrorCode::Internal, "internal", e.to_string()))
}

fn source_error(e: &BoxError) -> Fail {
    let code = match e {
        BoxError::Busy => ErrorCode::Busy,
        BoxError::Unavailable(_) => ErrorCode::Unavailable,
        BoxError::NotFound | BoxError::WrongState { .. } | BoxError::Invalid(_) => {
            ErrorCode::BadRequest
        }
    };
    Fail::Source(Refused::new(code, e.rule(), e.to_string()))
}

fn touch_required(action: &str) -> Fail {
    Fail::Policy(Refused::new(
        ErrorCode::Forbidden,
        "touch_required",
        format!("{action} needs a touch on a security key, which this version cannot check yet"),
    ))
}

/// The frame's args take only `keys`.
fn only(args: &Map<String, Value>, keys: &[&str]) -> Result<(), Fail> {
    match args.keys().find(|k| !keys.contains(&k.as_str())) {
        Some(k) => Err(invalid(format!("unexpected argument {k:?}"))),
        None => Ok(()),
    }
}

fn str_arg<'a>(args: &'a Map<String, Value>, k: &str) -> Result<&'a str, Fail> {
    args.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{k} is a string")))
}

fn id_arg(args: &Map<String, Value>) -> Result<BoxId, Fail> {
    BoxId::parse(str_arg(args, "id")?).map_err(|e| invalid(e.to_string()))
}

fn text_arg<'a>(args: &'a Map<String, Value>, k: &str, max: usize) -> Result<&'a str, Fail> {
    let s = str_arg(args, k)?;
    check_text(s, max).map_err(|e| invalid(format!("{k}: {e}")))?;
    Ok(s)
}

fn to_value<T: serde::Serialize>(t: &T) -> Result<Value, Fail> {
    serde_json::to_value(t).map_err(internal)
}

/// A box source call, off the runtime thread.
async fn blocking<T: Send + 'static>(
    ctx: &Arc<Ctx>,
    f: impl FnOnce(&dyn BoxSource) -> Result<T, BoxError> + Send + 'static,
) -> Result<T, Fail> {
    let boxes = Arc::clone(&ctx.boxes);
    match tokio::task::spawn_blocking(move || f(boxes.as_ref())).await {
        Ok(Ok(t)) => Ok(t),
        Ok(Err(e)) => Err(source_error(&e)),
        Err(e) => Err(internal(e)),
    }
}

async fn act(ctx: &Arc<Ctx>, v: &Verified, level: &mut Level) -> Result<Value, Fail> {
    let action = v.frame.action.as_str();
    let args = &v.frame.args;
    match v.level {
        // Plan 31 verifies touch proofs; until then none is acted on.
        Level::Touch => return Err(touch_required(action)),
        Level::MachineOnly => {
            return Err(Fail::Policy(Refused::new(
                ErrorCode::Forbidden,
                "machine_only",
                format!("{action} can only be done on the machine"),
            )))
        }
        Level::Signed => {}
    }
    if LATER.contains(&action) {
        return Err(Fail::Policy(Refused::new(
            ErrorCode::Unavailable,
            "unavailable",
            format!("{action} is not available in this version"),
        )));
    }
    match action {
        a::WORKSPACE_WHOAMI => {
            only(args, &[])?;
            let label = ctx.workspace.device(&v.device_id).map(|d| d.label);
            Ok(json!({
                "device_id": v.device_id,
                "label": label,
                "owner_user": v.owner_user,
            }))
        }
        a::BOX_OVERVIEW => {
            only(args, &[])?;
            to_value(&blocking(ctx, |b| Ok(b.overview())).await?)
        }
        a::BOX_LIST => {
            only(args, &[])?;
            to_value(&blocking(ctx, |b| Ok(b.list())).await?)
        }
        a::BOX_TEMPLATES => {
            only(args, &[])?;
            to_value(&blocking(ctx, |b| Ok(b.templates())).await?)
        }
        a::BOX_DIFF => {
            only(args, &["id"])?;
            let id = id_arg(args)?;
            to_value(&blocking(ctx, move |b| b.diff(&id)).await?)
        }
        a::BOX_TERM_READ => {
            only(args, &["id", "after"])?;
            let id = id_arg(args)?;
            let after = match args.get("after") {
                None | Some(Value::Null) => None,
                Some(x) => Some(x.as_u64().ok_or_else(|| invalid("after is a u64"))?),
            };
            to_value(&blocking(ctx, move |b| b.terminal(&id, after)).await?)
        }
        a::BOX_INBOX => {
            only(args, &[])?;
            let items: Vec<_> = blocking(ctx, |b| Ok(b.pending_actions()))
                .await?
                .iter()
                .map(|p| p.view())
                .collect();
            Ok(json!({ "items": to_value(&items)? }))
        }
        a::BOX_STOP | a::BOX_PAUSE | a::BOX_DISCARD => {
            only(args, &["id"])?;
            let id = id_arg(args)?;
            let name = action.to_string();
            blocking(ctx, move |b| match name.as_str() {
                a::BOX_STOP => b.stop(&id),
                a::BOX_PAUSE => b.pause(&id),
                _ => b.discard(&id),
            })
            .await?;
            Ok(json!({}))
        }
        a::BOX_REORDER => {
            only(args, &["ids"])?;
            let list = args
                .get("ids")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("ids is a list of box ids"))?;
            if list.len() > MAX_REORDER {
                return Err(invalid(format!("at most {MAX_REORDER} ids")));
            }
            let ids = list
                .iter()
                .map(|x| {
                    x.as_str()
                        .and_then(|s| BoxId::parse(s).ok())
                        .ok_or_else(|| invalid("ids is a list of box ids"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            blocking(ctx, move |b| b.reorder(&ids)).await?;
            Ok(json!({}))
        }
        a::BOX_SPAWN => {
            only(args, &["template", "repo", "task", "start"])?;
            let template = text_arg(args, "template", MAX_NAME_BYTES)?.to_string();
            let repo = text_arg(args, "repo", MAX_NAME_BYTES)?.to_string();
            let task = text_arg(args, "task", MAX_TASK_BYTES)?.to_string();
            let start = match args.get("start").and_then(Value::as_str) {
                Some("now") => Start::Now,
                Some("queue") => Start::Queue,
                _ => return Err(invalid("start is \"now\" or \"queue\"")),
            };
            let templates = blocking(ctx, |b| Ok(b.templates())).await?;
            let Some(t) = templates.iter().find(|t| t.name == template) else {
                return Err(invalid(format!("no template {template:?}")));
            };
            *level = spawn_level(t);
            if *level != Level::Signed {
                return Err(touch_required(action));
            }
            let req = SpawnReq {
                template,
                repo,
                task,
                start,
            };
            let id = blocking(ctx, move |b| b.spawn(&req)).await?;
            Ok(json!({ "id": id }))
        }
        a::LOCKDOWN_ON => {
            only(args, &["reason"])?;
            let reason = match args.get("reason") {
                None | Some(Value::Null) => String::new(),
                Some(Value::String(s)) => s.clone(),
                Some(_) => return Err(invalid("reason is a string")),
            };
            let Some(device) = ctx.workspace.device(&v.device_id) else {
                return Err(Fail::Policy(Refused::new(
                    ErrorCode::Forbidden,
                    "unknown_device",
                    "this device is no longer paired",
                )));
            };
            if let Err(e) = crate::lockdown::set_remote_on(ctx, &device, reason).await {
                return Err(Fail::Source(Refused::new(
                    ErrorCode::Internal,
                    e.rule(),
                    e.to_string(),
                )));
            }
            Ok(json!({
                "lockdown": crate::lockdown::status_json(ctx.lockdown.get().as_ref()),
            }))
        }
        other => Err(Fail::Policy(Refused::new(
            ErrorCode::Internal,
            "unhandled",
            format!("{other} has no handler"),
        ))),
    }
}

/// `workspace.sign` -> `{sig, device_pub?}`, for the two things link needs
/// and nothing else:
/// - `{purpose: "seal", data, device_id | pair_id}`: `data` is session_id ‖
///   machine_eph (81 bytes, a real P-256 point). Exactly one binding: a
///   `device_id` must be an Active device of the peer's uid (its key comes
///   back as `device_pub`); a `pair_id` an open offer begun by the peer's
///   user. The machine key signs `seal::machine_hello_msg(session_id,
///   machine_eph, binding)` (domain `MACHINE_HELLO_DOMAIN`), so the
///   signature opens a session for that device or offer only.
/// - `{purpose: "hub_hello", data}`: a 16..=64 byte nonce ‖ this machine's
///   id, for a peer that owns an Active device.
async fn sign(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value {
    let id = req.id;
    match sign_inner(ctx, conn, &req.args).await {
        Ok(m) => ok(id, m),
        Err(r) => r.answer(id),
    }
}

fn forbidden(rule: &'static str, message: &str) -> Refused {
    Refused::new(ErrorCode::Forbidden, rule, message)
}

/// Whether the peer's uid owns an Active device.
async fn owns_active_device(ctx: &Arc<Ctx>, peer_uid: u32) -> bool {
    let mut uids: HashMap<String, Option<u32>> = HashMap::new();
    for d in ctx.workspace.devices() {
        if d.state != DeviceState::Active {
            continue;
        }
        if !uids.contains_key(&d.owner_user) {
            let u = uid_of(ctx, &d.owner_user).await;
            uids.insert(d.owner_user.clone(), u);
        }
        if uids[&d.owner_user] == Some(peer_uid) {
            return true;
        }
    }
    false
}

async fn sign_inner(
    ctx: &Arc<Ctx>,
    conn: &Conn,
    args: &Map<String, Value>,
) -> Result<Map<String, Value>, Refused> {
    if ctx.workspace.locked() {
        return Err(locked());
    }
    const KEYS: [&str; 4] = ["purpose", "data", "device_id", "pair_id"];
    if let Some(k) = args.keys().find(|k| !KEYS.contains(&k.as_str())) {
        return Err(bad(format!("workspace.sign does not take {k:?}")));
    }
    let purpose = match args.get("purpose").and_then(Value::as_str) {
        Some("seal") => SignPurpose::Seal,
        Some("hub_hello") => SignPurpose::HubHello,
        _ => return Err(bad("purpose is \"seal\" or \"hub_hello\"")),
    };
    let data = args
        .get("data")
        .and_then(Value::as_str)
        .and_then(|s| b64::dec(s).ok())
        .ok_or_else(|| bad("data is b64u"))?;
    let opt = |k: &str| match args.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(bad(format!("{k} is a string"))),
    };
    let (device_id, pair_id) = (opt("device_id")?, opt("pair_id")?);
    let peer_uid = conn.peer.uid;
    let no_device = || {
        forbidden(
            "no_active_device",
            "the machine key signs only for a user with a paired device",
        )
    };
    let mut m = Map::new();
    let msg = match purpose {
        SignPurpose::HubHello => {
            if device_id.is_some() || pair_id.is_some() {
                return Err(bad("a hub hello takes no device_id or pair_id"));
            }
            let mid = ctx.workspace.machine_id();
            let shape_ok = data.len() >= mid.len()
                && HUB_NONCE.contains(&(data.len() - mid.len()))
                && data.ends_with(mid.as_bytes());
            if !shape_ok {
                return Err(bad("data is not a hub hello for this machine"));
            }
            if !owns_active_device(ctx, peer_uid).await {
                return Err(no_device());
            }
            data
        }
        SignPurpose::Seal => {
            let Ok(raw) = <[u8; 81]>::try_from(data.as_slice()) else {
                return Err(bad("seal data is session_id (16) ‖ machine_eph (65)"));
            };
            let mut sid = [0u8; 16];
            sid.copy_from_slice(&raw[..16]);
            let mut eph = [0u8; 65];
            eph.copy_from_slice(&raw[16..]);
            if !saiife_wire::sig::is_p256_point(&eph) {
                return Err(bad("machine_eph is not a P-256 point"));
            }
            let binding = match (device_id, pair_id) {
                (Some(dev), None) => {
                    if !owns_active_device(ctx, peer_uid).await {
                        return Err(no_device());
                    }
                    let d = ctx
                        .workspace
                        .device(&dev)
                        .ok_or_else(|| forbidden("unknown_device", "no such paired device"))?;
                    match d.state {
                        DeviceState::Active => {}
                        DeviceState::Pending => {
                            return Err(forbidden(
                                "device_pending",
                                "this device waits for confirmation on the machine",
                            ))
                        }
                        DeviceState::Revoked => {
                            return Err(forbidden("unknown_device", "no such paired device"))
                        }
                    }
                    if uid_of(ctx, &d.owner_user).await != Some(peer_uid) {
                        return Err(forbidden(
                            "wrong_owner",
                            "this device belongs to another user than the link process",
                        ));
                    }
                    m.insert("device_pub".into(), d.public_key.into());
                    SealBinding::Device(dev)
                }
                (None, Some(pid)) => {
                    let now = ctx.workspace.now();
                    // An offer that was spent (confirmed or rejected) is
                    // Expired even while its owner entry lingers.
                    let open = !matches!(
                        ctx.workspace.pair_status(&pid, now),
                        saiife_wire::pair::PairStatus::Expired
                    );
                    let Some(owner) = ctx.workspace.offer_owner(&pid, now).filter(|_| open) else {
                        return Err(forbidden(
                            "pair_expired",
                            "no open pairing offer under this pair_id",
                        ));
                    };
                    if uid_of(ctx, &owner).await != Some(peer_uid) {
                        return Err(forbidden(
                            "wrong_owner",
                            "this pairing was begun by another user than the link process",
                        ));
                    }
                    SealBinding::Pair(pid)
                }
                _ => return Err(bad("a seal takes exactly one of device_id and pair_id")),
            };
            machine_hello_msg(&sid, &eph, &binding)
        }
    };
    let sig = ctx.workspace.sign(purpose, &msg).map_err(|_| locked())?;
    m.insert("sig".into(), b64::enc(&sig).into());
    Ok(m)
}
