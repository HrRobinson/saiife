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
    OP_WORKSPACE_HELLO, OP_WORKSPACE_PAIR_FINISH, OP_WORKSPACE_SIGN, OP_WORKSPACE_WAKE,
};
use saiife_ipc::peer::comm;
use saiife_wire::device::DeviceState;
use saiife_wire::frame::{parse_body, SignedFrame, TouchProof};
use saiife_wire::level::{actions as a, spawn_level, Level};
use saiife_wire::pair::PairRequest;
use saiife_wire::seal::{machine_hello_msg, SealBinding};
use saiife_wire::source::{
    check_text, BoxError, BoxId, BoxSource, Decision, SpawnReq, Start, MAX_STEER_BYTES,
    MAX_TASK_BYTES,
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
    pub(crate) fn new(code: ErrorCode, rule: &'static str, message: impl Into<String>) -> Refused {
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

/// Remote actions no plan of this version fills in: `box.push` (plan 39
/// makes push a CLI-only, touch-bound path) and `box.pr`. Both answer
/// `unavailable`, with or without a touch.
pub const LATER: &[&str] = &["box.push", "box.pr"];

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
    a::WORKSPACE_TOUCH_BEGIN,
    a::APPROVAL_LIST,
    a::APPROVAL_REJECT,
];

/// The handled actions that change something: always recorded.
const CHANGES: &[&str] = &[
    a::BOX_LAND,
    a::BOX_STOP,
    a::BOX_PAUSE,
    a::BOX_DISCARD,
    a::BOX_REORDER,
    a::BOX_SPAWN,
    a::BOX_STEER,
    a::BOX_REVISE,
    a::BOX_RESUME,
    a::APPROVAL_APPROVE,
    a::APPROVAL_REJECT,
    a::LOCKDOWN_ON,
    a::WORKSPACE_TOUCH_BEGIN,
];

/// The most box ids a `box.reorder` takes.
const MAX_REORDER: usize = 256;
/// The longest template name and repo display name a `box.spawn` takes.
const MAX_NAME_BYTES: usize = 256;
/// The hub-hello nonce, in bytes.
const HUB_NONCE: std::ops::RangeInclusive<usize> = 16..=64;

/// `link.sock`: `hello`, `workspace.hello`, `workspace.pair.finish`,
/// `workspace.frame`, `workspace.sign` and `workspace.wake`. Any other op is `unknown_op`,
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
        OP_WORKSPACE_WAKE => wake(ctx, conn, req).await,
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
pub(crate) async fn uid_of(ctx: &Arc<Ctx>, user: &str) -> Option<u32> {
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

/// The checked credential of a pairing request's passkey (plan 31).
async fn passkey_for(
    ctx: &Arc<Ctx>,
    pr: &PairRequest,
    p: &saiife_wire::pair::PasskeyAttestation,
    now: u64,
) -> Result<saiife_touch::Credential, Refused> {
    let device_pub = saiife_wire::b64::dec_n::<65>(&pr.device_pub)
        .map_err(|e| Refused::new(ErrorCode::BadRequest, e.rule(), e.to_string()))?;
    let owner = ctx.workspace.offer_owner(&pr.pair_id, now).ok_or_else(|| {
        Refused::new(
            ErrorCode::Forbidden,
            "pair_expired",
            "this pairing has expired",
        )
    })?;
    let uid = uid_of(ctx, &owner).await.ok_or_else(|| {
        Refused::new(
            ErrorCode::Unavailable,
            "owner_unknown",
            "cannot resolve the user who began this pairing",
        )
    })?;
    saiife_touch::check_label(&pr.label)
        .map_err(|m| Refused::new(ErrorCode::BadRequest, "bad_request", m))?;
    let origins = crate::workspace_touch::origins(ctx);
    crate::workspace_touch::passkey_credential(
        p,
        &pr.pair_id,
        &device_pub,
        &origins,
        uid,
        &pr.label,
        &crate::ops::now_ts(),
    )
    .map_err(|m| Refused::new(ErrorCode::BadRequest, "passkey_refused", m))
}

/// `workspace.pair.finish {pair_id, device_pub, label, proof, passkey?}` ->
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
    // A passkey is checked in full before anything is held; one that fails
    // refuses the whole request (nothing is held, the offer stays open).
    let has_passkey = pr.passkey.is_some();
    let passkey = match &pr.passkey {
        None => None,
        Some(p) => match passkey_for(ctx, &pr, p, now).await {
            Ok(c) => Some(c),
            Err(r) => return r.answer(id),
        },
    };
    let (device, short_code) = match ctx.workspace.finish_pair_with(&pr, passkey, now) {
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
    if has_passkey {
        rec.extra.insert("passkey".into(), true.into());
    }
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
    // `check` has burned the nonce already: a frame refused below is spent.
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
    match run(ctx, &v, via, Some(conn), sf.touch.as_ref()).await {
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
/// refuses a Touch action without a verified `touch` proof (`touch_required`,
/// also `box.spawn` with a template that reaches secrets or the network) and
/// every name in [`LATER`], and records as the module says. Records written
/// through `execute` carry no peer (no `uid`, `user` or `peer` field): it
/// has no connection; `workspace.frame` on `link.sock` records its peer.
pub async fn execute(
    ctx: &Arc<Ctx>,
    v: &Verified,
    via: Via,
    touch: Option<&TouchProof>,
) -> Result<Value, Refused> {
    run(ctx, v, via, None, touch).await
}

/// Why an action failed: a refusal by the daemon (always recorded), or the
/// box source's error (recorded for a change only).
pub(crate) enum Fail {
    Policy(Refused),
    Source(Refused),
}

async fn run(
    ctx: &Arc<Ctx>,
    v: &Verified,
    via: Via,
    conn: Option<&Conn>,
    touch: Option<&TouchProof>,
) -> Result<Value, Refused> {
    let action = v.frame.action.as_str();
    let mut level = v.level;
    // The evidence of a touch that verified, kept for the record even when
    // the action then fails.
    let mut evidence: Option<Value> = None;
    // Whether a steer window (not a touch) covered the frame.
    let mut window = false;
    let mut out = act(ctx, v, &mut level, touch, &mut evidence, &mut window).await;
    // The begin's audit detail is not part of its answer.
    let begun = match (&mut out, action) {
        (Ok(Value::Object(m)), a::WORKSPACE_TOUCH_BEGIN) => m.remove("touch_begin"),
        _ => None,
    };
    // Nor is a revise's note (a held prompt sent ahead of it): it is the
    // record's reason.
    let noted = match (&mut out, action) {
        (Ok(Value::Object(m)), a::BOX_REVISE) => m.remove(REVISE_NOTE),
        _ => None,
    };
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
        if let Some(tb) = begun {
            rec.extra.insert("touch_begin".into(), tb);
        }
        if let Some(Value::String(n)) = noted {
            rec.reason = Some(n);
        }
        if let Some(ev) = evidence {
            rec.extra.insert("touch".into(), ev);
        }
        if window {
            rec.extra.insert("window".into(), true.into());
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

pub(crate) fn invalid(message: impl Into<String>) -> Fail {
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
        format!("{action} needs a touch: confirm it with your passkey"),
    ))
}

/// The frame's args take only `keys`.
/// FU1: the box's guard signal on a diff answer (unix: boxes exist there).
#[cfg(unix)]
fn add_guard(ctx: &Ctx, id: &BoxId, d: &mut Value) {
    if let (Some(o), Some(rec)) = (
        d.as_object_mut(),
        ctx.box_manager.as_ref().and_then(|m| m.get(id).ok()),
    ) {
        o.insert("guard".into(), crate::box_land::guard_json(&rec));
    }
}

#[cfg(not(unix))]
fn add_guard(_ctx: &Ctx, _id: &BoxId, _d: &mut Value) {}

pub(crate) fn only(args: &Map<String, Value>, keys: &[&str]) -> Result<(), Fail> {
    match args.keys().find(|k| !keys.contains(&k.as_str())) {
        Some(k) => Err(invalid(format!("unexpected argument {k:?}"))),
        None => Ok(()),
    }
}

pub(crate) fn str_arg<'a>(args: &'a Map<String, Value>, k: &str) -> Result<&'a str, Fail> {
    args.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{k} is a string")))
}

pub(crate) fn id_arg(args: &Map<String, Value>) -> Result<BoxId, Fail> {
    BoxId::parse(str_arg(args, "id")?).map_err(|e| invalid(e.to_string()))
}

pub(crate) fn text_arg<'a>(
    args: &'a Map<String, Value>,
    k: &str,
    max: usize,
) -> Result<&'a str, Fail> {
    let s = str_arg(args, k)?;
    check_text(s, max).map_err(|e| invalid(format!("{k}: {e}")))?;
    Ok(s)
}

fn to_value<T: serde::Serialize>(t: &T) -> Result<Value, Fail> {
    serde_json::to_value(t).map_err(internal)
}

/// A box source call, off the runtime thread.
pub(crate) async fn blocking<T: Send + 'static>(
    boxes: &Arc<dyn BoxSource>,
    f: impl FnOnce(&dyn BoxSource) -> Result<T, BoxError> + Send + 'static,
) -> Result<T, Fail> {
    let boxes = Arc::clone(boxes);
    match tokio::task::spawn_blocking(move || f(boxes.as_ref())).await {
        Ok(Ok(t)) => Ok(t),
        Ok(Err(e)) => Err(source_error(&e)),
        Err(e) => Err(internal(e)),
    }
}

/// The box source a frame's action runs on, built from the verified device
/// owner (never the shared `ctx.boxes`, when there is a manager): the owner
/// sees and changes their own boxes, another user's box is `not_found`. An
/// admin or root owner also SEES every box (reads only); changing another
/// user's box is `forbidden` (plan 34 R18). `args` are the action's own
/// args (the frame's, or a begin frame's inner ones): the boxes they name
/// are checked. Audited by `run` like any refusal.
pub(crate) async fn source_for(
    ctx: &Arc<Ctx>,
    v: &Verified,
    action: &str,
    args: &Map<String, Value>,
) -> Result<Arc<dyn BoxSource>, Fail> {
    let Some(m) = ctx.box_manager.clone().filter(|_| !ctx.workspace_demo) else {
        return Ok(Arc::clone(&ctx.boxes));
    };
    if !action.starts_with("box.") {
        return Ok(Arc::clone(&ctx.boxes));
    }
    let Some(owner) = uid_of(ctx, &v.owner_user).await else {
        return Err(Fail::Policy(Refused::new(
            ErrorCode::Forbidden,
            "unknown_owner",
            "the device owner is not a user of this machine",
        )));
    };
    let admin = owner == 0 || ctx.is_admin(owner).await;
    let reads = [
        a::BOX_OVERVIEW,
        a::BOX_LIST,
        a::BOX_TEMPLATES,
        a::BOX_DIFF,
        a::BOX_TERM_READ,
        a::BOX_INBOX,
    ];
    if admin && !reads.contains(&action) {
        // An admin changes only their own boxes: every box the frame names
        // (`id`, or reorder's `ids`).
        let named = args
            .get("id")
            .into_iter()
            .chain(
                args.get("ids")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten(),
            )
            .filter_map(Value::as_str)
            .filter_map(|s| BoxId::parse(s).ok());
        for id in named {
            if m.get(&id).is_ok_and(|r| r.owner_uid != owner) {
                return Err(Fail::Policy(Refused::new(
                    ErrorCode::Forbidden,
                    "not_owner",
                    "that box belongs to another user",
                )));
            }
        }
    }
    let scope = (!(admin && reads.contains(&action))).then_some(owner);
    match crate::box_ops::workspace_source(ctx, scope) {
        Some(src) => Ok(Arc::new(src)),
        None => Ok(Arc::clone(&ctx.boxes)),
    }
}

/// A Touch action: without a proof `touch_required`; with one, the proof
/// is verified (`workspace_touch::verify_frame`) and only then is anything
/// done. `box.land` completes its pending action with the evidence,
/// `box.spawn` spawns the box the touch bound and `approval.approve`
/// decides the request (`approval_ops::decide_remote`); any other action
/// is `unavailable`. The steer actions go through [`steer`].
async fn touched(
    ctx: &Arc<Ctx>,
    v: &Verified,
    proof: Option<&TouchProof>,
    evidence: &mut Option<Value>,
) -> Result<Value, Fail> {
    use crate::workspace_touch::Proven;
    let action = v.frame.action.as_str();
    let Some(proof) = proof else {
        return Err(touch_required(action));
    };
    let owner_uid = owner_uid_of(ctx, v).await?;
    // An approval's note is checked before its touch is verified (spent).
    let note = match (action, v.frame.args.get("note")) {
        (a::APPROVAL_APPROVE, Some(Value::String(n))) => {
            crate::approvals::check_note(n).map_err(|e| invalid(e.to_string()))?;
            Some(n.clone())
        }
        (a::APPROVAL_APPROVE, Some(Value::Null) | None) => None,
        (a::APPROVAL_APPROVE, Some(_)) => return Err(invalid("note is a string")),
        _ => None,
    };
    let src = source_for(ctx, v, action, &v.frame.args).await?;
    let proven = crate::workspace_touch::verify_frame(ctx, v, owner_uid, &src, proof)
        .await
        .map_err(Fail::Policy)?;
    *evidence = Some(proven.evidence().to_audit());
    match proven {
        Proven::Pending(ev, pa) if action == a::BOX_LAND => {
            let rid = pa.request_id;
            blocking(&src, move |b| b.complete(rid, Decision::Approve, Some(ev))).await?;
            Ok(json!({}))
        }
        Proven::Web(..) if action == a::BOX_SPAWN => {
            let req = spawn_req(&v.frame.args)?;
            let id = blocking(&src, move |b| b.spawn(&req)).await?;
            Ok(json!({ "id": id }))
        }
        Proven::Approval(ev, rid) if action == a::APPROVAL_APPROVE => {
            let device = device_of(ctx, v)?;
            crate::approval_ops::decide_remote(
                ctx,
                owner_uid,
                &v.owner_user,
                rid,
                true,
                note,
                Some(ev),
                &device,
            )
            .await
            .map_err(Fail::Policy)
        }
        _ => Err(Fail::Policy(Refused::new(
            ErrorCode::Unavailable,
            "unavailable",
            format!("{action} is not available in this version"),
        ))),
    }
}

/// The frame's device, still paired.
fn device_of(ctx: &Arc<Ctx>, v: &Verified) -> Result<saiife_wire::device::Device, Fail> {
    ctx.workspace.device(&v.device_id).ok_or_else(|| {
        Fail::Policy(Refused::new(
            ErrorCode::Forbidden,
            "unknown_device",
            "this device is no longer paired",
        ))
    })
}

/// `box.steer {id, msg}`, `box.revise {id, comment}`, `box.resume {id}`.
/// A verified touch for the box opens the device's window on it
/// ([`WebTouches::open_window`](crate::workspace_touch::WebTouches)) and the
/// action runs; without a proof, an open window on exactly this box lets it
/// run (recorded `window: true`); else `touch_required`. The text is checked
/// before a proof is verified, so a bad text does not spend the touch. The
/// window opens on the verified touch, before the action runs: it stays
/// open even when the action then fails (a `WrongState`, say), since the
/// touch proved presence for that box all the same.
async fn steer(
    ctx: &Arc<Ctx>,
    v: &Verified,
    proof: Option<&TouchProof>,
    evidence: &mut Option<Value>,
    window: &mut bool,
) -> Result<Value, Fail> {
    use crate::workspace_touch::Proven;
    let action = v.frame.action.as_str();
    let args = &v.frame.args;
    let now = ctx.workspace.now();
    if proof.is_none() {
        let covered =
            id_arg(args).is_ok_and(|id| ctx.web_touch.window_open(&v.device_id, &id, now));
        if !covered {
            return Err(touch_required(action));
        }
    }
    let text_key = match action {
        a::BOX_STEER => Some("msg"),
        a::BOX_REVISE => Some("comment"),
        _ => None,
    };
    match text_key {
        Some(k) => only(args, &["id", k])?,
        None => only(args, &["id"])?,
    }
    let id = id_arg(args)?;
    let text = match text_key {
        Some(k) => Some(text_arg(args, k, MAX_STEER_BYTES)?.to_string()),
        None => None,
    };
    let owner_uid = owner_uid_of(ctx, v).await?;
    let src = source_for(ctx, v, action, args).await?;
    match proof {
        Some(p) => {
            let proven = crate::workspace_touch::verify_frame(ctx, v, owner_uid, &src, p)
                .await
                .map_err(Fail::Policy)?;
            *evidence = Some(proven.evidence().to_audit());
            if !matches!(proven, Proven::Web(..)) {
                return Err(Fail::Policy(Refused::new(
                    ErrorCode::Internal,
                    "internal",
                    "a steer touch did not verify as one",
                )));
            }
            ctx.web_touch.open_window(&v.device_id, &id, now);
        }
        None => *window = true,
    }
    let name = action.to_string();
    let note = blocking(&src, move |b| match (name.as_str(), text) {
        (a::BOX_STEER, Some(t)) => b.steer(&id, &t).map(|()| None),
        (a::BOX_REVISE, Some(t)) => b.revise_noted(&id, &t),
        _ => b.resume(&id).map(|()| None),
    })
    .await?;
    // The frame takes the note into its record, not its answer.
    Ok(match note {
        Some(n) => json!({ REVISE_NOTE: n }),
        None => json!({}),
    })
}

/// The answer key `steer` passes a revise's note to `frame` in (R25/N1).
const REVISE_NOTE: &str = "revise_note";

/// The device owner's uid.
async fn owner_uid_of(ctx: &Arc<Ctx>, v: &Verified) -> Result<u32, Fail> {
    uid_of(ctx, &v.owner_user).await.ok_or_else(|| {
        Fail::Policy(Refused::new(
            ErrorCode::Forbidden,
            "unknown_owner",
            "the device owner is not a user of this machine",
        ))
    })
}

/// The `box.spawn` args as a request (the caller has checked the template).
fn spawn_req(args: &Map<String, Value>) -> Result<SpawnReq, Fail> {
    only(args, &["template", "repo", "task", "start"])?;
    let template = text_arg(args, "template", MAX_NAME_BYTES)?.to_string();
    let repo = text_arg(args, "repo", MAX_NAME_BYTES)?.to_string();
    let task = text_arg(args, "task", MAX_TASK_BYTES)?.to_string();
    let start = match args.get("start").and_then(Value::as_str) {
        Some("now") => Start::Now,
        Some("queue") => Start::Queue,
        _ => return Err(invalid("start is \"now\" or \"queue\"")),
    };
    Ok(SpawnReq {
        template,
        repo,
        task,
        start,
    })
}

async fn act(
    ctx: &Arc<Ctx>,
    v: &Verified,
    level: &mut Level,
    touch: Option<&TouchProof>,
    evidence: &mut Option<Value>,
    window: &mut bool,
) -> Result<Value, Fail> {
    let action = v.frame.action.as_str();
    let args = &v.frame.args;
    // One lockdown gate for box power, shared with the control socket.
    if let Some(why) = crate::box_ops::power_refusal(ctx, action) {
        return Err(Fail::Policy(Refused::new(
            ErrorCode::Lockdown,
            "lockdown",
            why,
        )));
    }
    match v.level {
        // box.push and box.pr stay unavailable (the LATER check below).
        Level::Touch if matches!(action, a::BOX_PUSH | a::BOX_PR) => {}
        Level::Touch if matches!(action, a::BOX_STEER | a::BOX_REVISE | a::BOX_RESUME) => {
            return steer(ctx, v, touch, evidence, window).await
        }
        Level::Touch => return touched(ctx, v, touch, evidence).await,
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
    let src = source_for(ctx, v, action, args).await?;
    match action {
        a::WORKSPACE_WHOAMI => {
            only(args, &[])?;
            let device = ctx.workspace.device(&v.device_id);
            let label = device.as_ref().map(|d| d.label.clone());
            // The passkeys a touch from this browser may use, as the daemon
            // holds them (none when the owner is unknown: fail closed).
            let passkeys: Vec<String> = match (device, uid_of(ctx, &v.owner_user).await) {
                (Some(d), Some(uid)) => {
                    crate::workspace_touch::device_passkeys(ctx, uid, d.touch_credentials)
                        .await
                        .map_err(Fail::Policy)?
                        .iter()
                        .map(|c| saiife_wire::b64::enc(&c.id))
                        .collect()
                }
                _ => Vec::new(),
            };
            Ok(json!({
                "device_id": v.device_id,
                "label": label,
                "owner_user": v.owner_user,
                "passkeys": passkeys,
            }))
        }
        a::BOX_OVERVIEW => {
            only(args, &[])?;
            to_value(&blocking(&src, |b| Ok(b.overview())).await?)
        }
        a::BOX_LIST => {
            only(args, &[])?;
            to_value(&blocking(&src, |b| Ok(b.list())).await?)
        }
        a::BOX_TEMPLATES => {
            only(args, &[])?;
            to_value(&blocking(&src, |b| Ok(b.templates())).await?)
        }
        a::BOX_DIFF => {
            only(args, &["id"])?;
            let id = id_arg(args)?;
            let gid = id.clone();
            let mut d = to_value(&blocking(&src, move |b| b.diff(&id)).await?)?;
            // FU1: the box's guard signal; the source answered, so the
            // frame's owner may see this box.
            add_guard(ctx, &gid, &mut d);
            Ok(d)
        }
        a::BOX_TERM_READ => {
            only(args, &["id", "after"])?;
            let id = id_arg(args)?;
            let after = match args.get("after") {
                None | Some(Value::Null) => None,
                Some(x) => Some(x.as_u64().ok_or_else(|| invalid("after is a u64"))?),
            };
            to_value(&blocking(&src, move |b| b.terminal(&id, after)).await?)
        }
        a::BOX_INBOX => {
            only(args, &[])?;
            let items: Vec<_> = blocking(&src, |b| Ok(b.pending_actions()))
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
            blocking(&src, move |b| match name.as_str() {
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
            blocking(&src, move |b| b.reorder(&ids)).await?;
            Ok(json!({}))
        }
        a::BOX_SPAWN => {
            let req = spawn_req(args)?;
            let templates = blocking(&src, |b| Ok(b.templates())).await?;
            let Some(t) = templates.iter().find(|t| t.name == req.template) else {
                return Err(invalid(format!("no template {:?}", req.template)));
            };
            *level = spawn_level(t);
            if *level != Level::Signed {
                return touched(ctx, v, touch, evidence).await;
            }
            let id = blocking(&src, move |b| b.spawn(&req)).await?;
            Ok(json!({ "id": id }))
        }
        a::APPROVAL_LIST => {
            only(args, &[])?;
            let owner_uid = owner_uid_of(ctx, v).await?;
            let items = crate::approval_ops::list_remote(ctx, owner_uid, &v.owner_user)
                .await
                .map_err(Fail::Policy)?;
            Ok(json!({ "items": items }))
        }
        a::APPROVAL_REJECT => {
            only(args, &["id", "note"])?;
            let rid = args
                .get("id")
                .and_then(Value::as_u64)
                .ok_or_else(|| invalid("id is a request number"))?;
            let note = match args.get("note") {
                None | Some(Value::Null) => None,
                Some(Value::String(s)) => {
                    crate::approvals::check_note(s).map_err(|e| invalid(e.to_string()))?;
                    Some(s.clone())
                }
                Some(_) => return Err(invalid("note is a string")),
            };
            let owner_uid = owner_uid_of(ctx, v).await?;
            let device = device_of(ctx, v)?;
            crate::approval_ops::decide_remote(
                ctx,
                owner_uid,
                &v.owner_user,
                rid,
                false,
                note,
                None,
                &device,
            )
            .await
            .map_err(Fail::Policy)
        }
        a::WORKSPACE_TOUCH_BEGIN => crate::workspace_touch::begin(ctx, v)
            .await
            .map_err(Fail::Policy),
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
///   id, for a peer that owns an Active device or may pair on this machine
///   (root, `[admin] groups`, an `[approval] approvers` member: the people
///   `workspace.pair.begin` serves, without re-authentication; the hub
///   hello grants nothing, and the first phone pairs over the hub). Anyone
///   else: `forbidden`, rule `no_active_device`.
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

/// Whether the peer may pair devices on this machine (an admin or an
/// approver, as `workspace_ops` decides for `workspace.pair.begin`).
async fn may_pair(ctx: &Arc<Ctx>, peer: &saiife_ipc::peer::PeerCred) -> bool {
    ctx.peer_is_admin(peer).await || crate::approval_ops::is_approver(ctx, peer).await
}

/// `workspace.wake`: `{}` -> `{push, seq}` for the hub link's content-free
/// wake-ups. Only a peer who may hold the hub link (as for a `hub_hello`
/// sign) learns the count. Never recorded.
async fn wake(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value {
    if ctx.workspace.locked() {
        return locked().answer(req.id);
    }
    if let Some(k) = req.args.keys().next() {
        return bad(format!("workspace.wake does not take {k:?}")).answer(req.id);
    }
    if !owns_active_device(ctx, conn.peer.uid).await && !may_pair(ctx, &conn.peer).await {
        return forbidden(
            "no_active_device",
            "hub wake-ups are only for a user with a paired device or one who may pair",
        )
        .answer(req.id);
    }
    let push = ctx.policy().system.is_some_and(|s| s.workspace.push);
    let mut m = Map::new();
    m.insert("push".into(), push.into());
    m.insert("seq".into(), ctx.workspace.wakes().into());
    ok(req.id, m)
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
            if !owns_active_device(ctx, peer_uid).await && !may_pair(ctx, &conn.peer).await {
                return Err(forbidden(
                    "no_active_device",
                    "the machine key signs a hub hello only for a user with a paired device \
                     or one who may pair on this machine",
                ));
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
