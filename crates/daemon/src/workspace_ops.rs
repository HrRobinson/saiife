//! The Workspace link ops (plan 29, Tasks 3 and 4).
//!
//! Task 3, the machine side on the control socket (`saiife.sock`):
//! `workspace.pair.begin`, `.pair.status`, `.pair.confirm`, `workspace.devices`
//! and `workspace.revoke`. These are the only ways to add or remove a
//! trusted device; `link.sock` has no route to them.
//!
//! Task 4, `link.sock`: [`dispatch_link`] and [`execute`], in
//! `crate::workspace_link` and re-exported here.

use crate::ops::{Conn, Ctx};
// Task 4, link.sock (`crate::workspace_link`).
pub use crate::workspace_link::{dispatch_link, execute, Refused, Via, HANDLED, LATER};
use saiife_audit::{DecisionKind, Record};
use saiife_ipc::msg::{
    err, err_with, ok, ErrorCode, Request, OP_WORKSPACE_DEVICES, OP_WORKSPACE_PAIR_BEGIN,
    OP_WORKSPACE_PAIR_CONFIRM, OP_WORKSPACE_PAIR_STATUS, OP_WORKSPACE_REVOKE,
};
use saiife_ipc::peer::comm;
use saiife_wire::pair::{self, PairStatus};
use saiife_wire::WireError;
use serde_json::{json, Map, Value};
use std::sync::{Arc, Mutex};

/// The polkit `--detail` of confirming a pairing (as `lockdown::OFF_DETAIL`).
pub const PAIR_DETAIL: &str = "workspace pair";
/// The polkit `--detail` of revoking a device.
pub const REVOKE_DETAIL: &str = "workspace revoke";
/// The longest label a person gives an offer (as the wire's device labels).
const MAX_LABEL_CHARS: usize = 40;

/// `workspace.pair.begin | .pair.status | .pair.confirm | workspace.devices |
/// workspace.revoke` on the control socket.
///
/// Who: root and `[admin] groups`, or an `[approval] approvers` member (in
/// the personal broker, its own user). `pair.begin`, `pair.status`,
/// `devices` and a reject need nothing more. Granting power (`pair.confirm`
/// with `accept: true`, `revoke`) makes an approver pass
/// [`crate::lockdown::may_turn_off`], i.e. `same_user` re-authentication,
/// refused like `lockdown off`. `pair.status` is for the user who began the
/// offer only; `pair.confirm` for that user or an admin.
pub async fn handle(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value {
    match req.op.as_str() {
        OP_WORKSPACE_PAIR_BEGIN => begin(ctx, conn, req).await,
        OP_WORKSPACE_PAIR_STATUS => status(ctx, conn, req).await,
        OP_WORKSPACE_PAIR_CONFIRM => confirm(ctx, conn, req).await,
        OP_WORKSPACE_DEVICES => devices(ctx, conn, req).await,
        OP_WORKSPACE_REVOKE => revoke(ctx, conn, req).await,
        other => err(
            req.id,
            ErrorCode::UnknownOp,
            &format!("unknown op {other:?}"),
        ),
    }
}

/// What the caller is.
struct Caller {
    admin: bool,
    /// The daemon's own lookup of the caller's name.
    name: String,
}

/// A `workspace` record for `action`, with the caller's identity.
async fn record(ctx: &Arc<Ctx>, conn: &Conn, action: &str) -> Record {
    let peer = &conn.peer;
    let mut rec = ctx.record("workspace", action);
    rec.uid = Some(peer.uid);
    rec.sid = peer.sid.clone();
    rec.user = ctx.peer_name(peer).await;
    rec.extra.insert("action".into(), action.into());
    rec.extra.insert(
        "peer".into(),
        json!({"pid": peer.pid, "comm": comm(peer.pid)}),
    );
    rec
}

async fn append(ctx: &Arc<Ctx>, rec: Record) {
    if let Err(e) = ctx.writer.append(rec).await {
        eprintln!("saiifed: warning: cannot write workspace record: {e}");
    }
}

/// Writes a `deny` record with `rule` and answers `code`.
async fn refuse(
    ctx: &Arc<Ctx>,
    conn: &Conn,
    id: u64,
    action: &str,
    code: ErrorCode,
    rule: &str,
    why: &str,
) -> Value {
    let mut rec = record(ctx, conn, action).await;
    rec.decision = DecisionKind::Deny;
    rec.rule = Some(rule.into());
    rec.reason = Some(why.into());
    append(ctx, rec).await;
    let mut m = Map::new();
    m.insert("rule".into(), rule.into());
    err_with(id, code, why, m)
}

/// Admin or approver, else a `forbidden` answer (and a `deny` record).
async fn caller(ctx: &Arc<Ctx>, conn: &Conn, id: u64, action: &str) -> Result<Caller, Value> {
    let admin = ctx.peer_is_admin(&conn.peer).await;
    if !admin && !crate::approval_ops::is_approver(ctx, &conn.peer).await {
        return Err(refuse(
            ctx,
            conn,
            id,
            action,
            ErrorCode::Forbidden,
            "forbidden",
            "the Workspace is for root, [admin] groups and [approval] approvers",
        )
        .await);
    }
    // A pairing belongs to a user name; only the daemon's own lookup counts.
    match ctx.peer_name(&conn.peer).await.filter(|n| !n.is_empty()) {
        Some(name) => Ok(Caller { admin, name }),
        None => Err(err(
            id,
            ErrorCode::Unavailable,
            "cannot resolve your user name",
        )),
    }
}

/// The re-authentication that grants power: none for an admin; an approver
/// passes `may_turn_off` (same text and rule as a refused `lockdown off`).
async fn power(
    ctx: &Arc<Ctx>,
    conn: &Conn,
    id: u64,
    action: &str,
    who: &Caller,
    (detail, what): (&'static str, &str),
    auth: Option<[u8; 32]>,
) -> Result<(), Value> {
    if who.admin {
        return Ok(());
    }
    match crate::lockdown::may_turn_off(ctx, conn, detail, auth).await {
        Ok(()) => Ok(()),
        Err(r) => {
            let (rule, why) = crate::lockdown::off_refusal(&r, what);
            Err(refuse(
                ctx,
                conn,
                id,
                action,
                ErrorCode::Forbidden,
                rule,
                &format!("refused ({rule}): {why}"),
            )
            .await)
        }
    }
}

fn str_arg<'a>(req: &'a Request, name: &str) -> Result<&'a str, Value> {
    match req.args.get(name) {
        Some(Value::String(s)) if !s.is_empty() && s.len() <= 256 => Ok(s),
        _ => Err(err(
            req.id,
            ErrorCode::BadRequest,
            &format!("{} takes {name}: a string", req.op),
        )),
    }
}

fn auth_of(req: &Request) -> Result<Option<[u8; 32]>, Value> {
    crate::approval_ops::auth_arg(&req.args).map_err(|e| err(req.id, ErrorCode::BadRequest, &e))
}

/// The answer to a change whose record could not be written.
fn unrecorded(id: u64, what: &str, e: &str) -> Value {
    err(
        id,
        ErrorCode::Unrecorded,
        &format!("{what}, but its record could not be written: {e}"),
    )
}

fn wire_code(e: &WireError) -> ErrorCode {
    match e {
        WireError::PairFull => ErrorCode::Busy,
        WireError::Store(_) => ErrorCode::Unavailable,
        WireError::Malformed(_) => ErrorCode::BadRequest,
        _ => ErrorCode::Internal,
    }
}

/// `workspace.pair.begin {label?}` -> `{pair_id, fragment, machine_id,
/// expires_at}`. The fragment holds the offer's secret: it is only in this
/// answer, never in a record or a log.
async fn begin(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value {
    let id = req.id;
    let label = match req.args.get("label") {
        None | Some(Value::Null) => None,
        Some(Value::String(s))
            if s.chars().count() <= MAX_LABEL_CHARS && !s.chars().any(char::is_control) =>
        {
            Some(s.clone())
        }
        Some(_) => {
            return err(
                id,
                ErrorCode::BadRequest,
                "label is a string of at most 40 characters without control characters",
            )
        }
    };
    let who = match caller(ctx, conn, id, "pair_offer").await {
        Ok(w) => w,
        Err(e) => return e,
    };
    let now = ctx.workspace.now();
    let offer = match ctx.workspace.begin_pair(&who.name, label.clone(), now) {
        Ok(o) => o,
        Err(e) => return err(id, wire_code(&e), &e.to_string()),
    };
    let mut rec = record(ctx, conn, "pair_offer").await;
    rec.extra.insert("label".into(), json!(label));
    rec.extra
        .insert("pair_id".into(), offer.pair_id.clone().into());
    rec.extra
        .insert("expires_at".into(), offer.expires_at.into());
    if let Err(e) = ctx.writer.append(rec).await {
        // The fragment is withheld; the offer lapses unused.
        return unrecorded(id, "the offer is open", &e);
    }
    let mut m = Map::new();
    m.insert("pair_id".into(), offer.pair_id.clone().into());
    m.insert("fragment".into(), pair::fragment(&offer).into());
    m.insert("machine_id".into(), offer.machine_id.clone().into());
    m.insert("expires_at".into(), offer.expires_at.into());
    ok(id, m)
}

/// `workspace.pair.status {pair_id}` -> the wire's `PairStatus`. Only for the
/// user who began the offer (not even an admin: the short code is for the
/// person at the screen).
async fn status(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value {
    let id = req.id;
    let pair_id = match str_arg(&req, "pair_id") {
        Ok(p) => p.to_string(),
        Err(e) => return e,
    };
    let who = match caller(ctx, conn, id, "pair_status").await {
        Ok(w) => w,
        Err(e) => return e,
    };
    let now = ctx.workspace.now();
    if ctx
        .workspace
        .offer_owner(&pair_id, now)
        .is_some_and(|o| o != who.name)
    {
        return refuse(
            ctx,
            conn,
            id,
            "pair_status",
            ErrorCode::Forbidden,
            "forbidden",
            "this pairing was begun by another user",
        )
        .await;
    }
    let st = serde_json::to_value(ctx.workspace.pair_status(&pair_id, now)).unwrap_or(Value::Null);
    let mut m = st.as_object().cloned().unwrap_or_default();
    m.remove("id");
    ok(id, m)
}

/// `workspace.pair.confirm {pair_id, accept, auth?}` -> `{device_id, state}`
/// (`active` or `rejected`). The user who began the offer or an admin may
/// confirm. A reject grants nothing and needs no re-authentication; an accept
/// does (an approver passes `may_turn_off`).
async fn confirm(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value {
    let id = req.id;
    let pair_id = match str_arg(&req, "pair_id") {
        Ok(p) => p.to_string(),
        Err(e) => return e,
    };
    let Some(accept) = req.args.get("accept").and_then(Value::as_bool) else {
        return err(
            id,
            ErrorCode::BadRequest,
            "workspace.pair.confirm takes accept: true|false",
        );
    };
    let auth = match auth_of(&req) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let action = if accept { "paired" } else { "pair_rejected" };
    let who = match caller(ctx, conn, id, action).await {
        Ok(w) => w,
        Err(e) => return e,
    };
    let now = ctx.workspace.now();
    if !who.admin
        && ctx
            .workspace
            .offer_owner(&pair_id, now)
            .is_none_or(|o| o != who.name)
    {
        return refuse(
            ctx,
            conn,
            id,
            action,
            ErrorCode::Forbidden,
            "forbidden",
            "only the user who began this pairing, or an admin, can confirm it",
        )
        .await;
    }
    if accept && ctx.workspace.locked() {
        return refuse(
            ctx,
            conn,
            id,
            action,
            ErrorCode::Unavailable,
            "workspace_locked",
            "the Workspace is locked (see the daemon's start warning); nothing is paired",
        )
        .await;
    }
    // Nothing waiting: say so before any prompt.
    let PairStatus::Requested {
        short_code,
        label,
        device_id,
    } = ctx.workspace.pair_status(&pair_id, now)
    else {
        return err(
            id,
            ErrorCode::BadRequest,
            "no device is waiting under this pair_id (it expired, or no device answered)",
        );
    };
    if accept {
        if let Err(e) = power(
            ctx,
            conn,
            id,
            action,
            &who,
            (PAIR_DETAIL, "pairing a device"),
            auth,
        )
        .await
        {
            return e;
        }
    }
    // The prompt can take minutes: an offer that expired meanwhile is gone.
    let now = ctx.workspace.now();
    // The held passkey is stored first (in a blocking task: it writes the
    // touch files); a device save that fails takes it out again.
    let added: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let not_saved: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let confirmed = {
        let (ctx, pair_id, added, not_saved) = (
            Arc::clone(ctx),
            pair_id.clone(),
            Arc::clone(&added),
            Arc::clone(&not_saved),
        );
        tokio::task::spawn_blocking(move || {
            ctx.workspace
                .confirm_pair_with(&pair_id, accept, now, &|c| match ctx.touch.add(c.clone()) {
                    Ok(()) => {
                        *added.lock().unwrap_or_else(|e| e.into_inner()) = Some(c.id.clone());
                        Ok(())
                    }
                    Err(e) => {
                        *not_saved.lock().unwrap_or_else(|e| e.into_inner()) = Some(e.clone());
                        Err(e)
                    }
                })
        })
        .await
        .unwrap_or_else(|e| Err(std::io::Error::other(e.to_string())))
    };
    if confirmed.is_err() {
        let stored = added.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(cid) = stored {
            let _ = ctx.touch.remove(&cid);
        }
    }
    let device = match confirmed {
        Ok(d) => d,
        Err(e) => {
            let rule = if ctx.workspace.locked() {
                "workspace_locked"
            } else {
                "workspace_not_saved"
            };
            return refuse(
                ctx,
                conn,
                id,
                action,
                ErrorCode::Internal,
                rule,
                &format!("the device was not paired: {e}"),
            )
            .await;
        }
    };
    if accept && device.is_none() {
        return err(
            id,
            ErrorCode::BadRequest,
            "the pairing lapsed before it was confirmed; begin a new one",
        );
    }
    let mut rec = record(ctx, conn, action).await;
    rec.extra.insert("device".into(), device_id.clone().into());
    rec.extra.insert("label".into(), label.into());
    rec.extra.insert("pair_id".into(), pair_id.into());
    if let Some(d) = &device {
        rec.extra
            .insert("owner".into(), d.owner_user.clone().into());
        rec.extra.insert("short_code".into(), short_code.into());
    }
    let state = if accept { "active" } else { "rejected" };
    // `extra.passkey` is the stored credential's id, or null.
    let passkey = device
        .as_ref()
        .and_then(|d| d.touch_credentials.first().cloned());
    let reason = not_saved.lock().unwrap_or_else(|e| e.into_inner()).take();
    if accept {
        rec.extra.insert("passkey".into(), json!(passkey));
    }
    if let Err(e) = ctx.writer.append(rec).await {
        return unrecorded(id, &format!("the device is {state}"), &e);
    }
    let mut m = Map::new();
    m.insert("device_id".into(), device_id.into());
    m.insert("state".into(), state.into());
    if let Some(p) = passkey {
        m.insert("passkey".into(), p.into());
    } else if let Some(why) = reason {
        m.insert("passkey".into(), "not_saved".into());
        m.insert("passkey_reason".into(), why.into());
    }
    ok(id, m)
}

/// `workspace.devices {}` -> `{devices: [Device without public_key]}`.
async fn devices(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value {
    if let Err(e) = caller(ctx, conn, req.id, "devices").await {
        return e;
    }
    let list: Vec<Value> = ctx
        .workspace
        .devices()
        .iter()
        .filter_map(|d| serde_json::to_value(d).ok())
        .map(|mut v| {
            if let Some(o) = v.as_object_mut() {
                o.remove("public_key");
            }
            v
        })
        .collect();
    let mut m = Map::new();
    m.insert("devices".into(), list.into());
    ok(req.id, m)
}

/// `workspace.revoke {device_id, auth?}` -> `{device_id, state: "revoked"}`.
/// The device is refused as soon as the daemon has marked it. When
/// `devices.json` cannot be written the answer is an `internal` error that
/// says so (the revocation is in effect but must be repeated), and the
/// `revoked` record carries `saved: false` and "not saved".
async fn revoke(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value {
    let id = req.id;
    let device_id = match str_arg(&req, "device_id") {
        Ok(d) => d.to_string(),
        Err(e) => return e,
    };
    let auth = match auth_of(&req) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let who = match caller(ctx, conn, id, "revoked").await {
        Ok(w) => w,
        Err(e) => return e,
    };
    let Some(device) = ctx.workspace.device(&device_id) else {
        return err(id, ErrorCode::BadRequest, "no such device");
    };
    // Already revoked and saved: nothing to grant, no prompt. Any passkey a
    // failed removal left behind is taken out now (a retry).
    if ctx.workspace.revoked_and_saved(&device_id) {
        remove_passkeys(ctx, conn, &device_id, &device.touch_credentials).await;
        return revoked_answer(id, device_id);
    }
    if let Err(e) = power(
        ctx,
        conn,
        id,
        "revoked",
        &who,
        (REVOKE_DETAIL, "revoking a device"),
        auth,
    )
    .await
    {
        return e;
    }
    let outcome = ctx.workspace.revoke(&device_id);
    // The revoke is in effect in memory now (plan 29 ordering). Its passkeys
    // leave the touch store next; a failure there never undoes the revoke.
    remove_passkeys(ctx, conn, &device_id, &device.touch_credentials).await;
    let mut rec = record(ctx, conn, "revoked").await;
    rec.extra.insert("device".into(), device_id.clone().into());
    rec.extra.insert("label".into(), device.label.into());
    rec.extra.insert("owner".into(), device.owner_user.into());
    // Already revoked and saved: nothing changed, nothing to record.
    if matches!(outcome, Ok(false)) {
        return revoked_answer(id, device_id);
    }
    let mut problem = None;
    if let Err(e) = &outcome {
        rec.extra.insert("saved".into(), false.into());
        rec.reason = Some(format!("revoked, not saved: {e}"));
        problem = Some(e.to_string());
    }
    let recorded = ctx.writer.append(rec).await;
    if let Some(m) = problem {
        return err(id, ErrorCode::Internal, &m);
    }
    if let Err(e) = recorded {
        return unrecorded(id, "the device is revoked", &e);
    }
    revoked_answer(id, device_id)
}

/// Removes a revoked device's passkeys from the touch store (in a blocking
/// task) and audits `touch_removed {device, credentials, failed?, reason?}`
/// (credential ids b64u). Nothing is audited when none of them was in the
/// store. A failed removal is logged and audited and leaves the revoke as it
/// is (fail closed).
async fn remove_passkeys(ctx: &Arc<Ctx>, conn: &Conn, device_id: &str, creds: &[String]) {
    if creds.is_empty() {
        return;
    }
    let ids: Vec<String> = creds.to_vec();
    let c = Arc::clone(ctx);
    let (removed, failed) = tokio::task::spawn_blocking(move || {
        let (mut removed, mut failed) = (Vec::new(), Vec::new());
        for id in ids {
            let Ok(raw) = saiife_wire::b64::dec(&id) else {
                failed.push((id, "not a credential id".to_string()));
                continue;
            };
            match c.touch.remove(&raw) {
                Ok(Some(_)) => removed.push(id),
                Ok(None) => {}
                Err(e) => failed.push((id, e)),
            }
        }
        (removed, failed)
    })
    .await
    .unwrap_or_else(|e| {
        (
            Vec::new(),
            creds.iter().map(|c| (c.clone(), e.to_string())).collect(),
        )
    });
    if removed.is_empty() && failed.is_empty() {
        return;
    }
    let mut rec = record(ctx, conn, "touch_removed").await;
    rec.extra.insert("device".into(), device_id.into());
    rec.extra.insert("credentials".into(), json!(removed));
    if !failed.is_empty() {
        let ids: Vec<&String> = failed.iter().map(|(i, _)| i).collect();
        rec.extra.insert("failed".into(), json!(ids));
        let why = failed
            .iter()
            .map(|(_, e)| e.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        rec.decision = DecisionKind::Deny;
        rec.rule = Some("touch_not_removed".into());
        rec.reason = Some(format!(
            "the device is revoked, but its passkey stays in the touch store: {why}"
        ));
        eprintln!("saiifed: warning: revoked device {device_id}: cannot remove its passkey: {why}");
    }
    if let Err(e) = ctx.writer.append(rec).await {
        eprintln!("saiifed: warning: cannot write the touch_removed record: {e}");
    }
}

fn revoked_answer(id: u64, device_id: String) -> Value {
    let mut m = Map::new();
    m.insert("device_id".into(), device_id.into());
    m.insert("state".into(), "revoked".into());
    ok(id, m)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::ops::{Mode, PolicyState};
    use crate::reauth::{Reauth, ReauthResult, Subject};
    use crate::sessions::{Proc, ProcStat};
    use saiife_ipc::msg::{
        OP_WORKSPACE_DEVICES, OP_WORKSPACE_PAIR_BEGIN, OP_WORKSPACE_PAIR_CONFIRM,
        OP_WORKSPACE_PAIR_STATUS, OP_WORKSPACE_REVOKE,
    };
    use saiife_ipc::peer::PeerCred;
    use saiife_wire::pair::{proof, PairRequest};
    use saiife_wire::sig::TestDevice;
    use saiife_wire::{b64, pair};
    use serde_json::json;
    use std::sync::Mutex;
    use std::time::Duration;

    const PASSWD: &str = "root:x:0:0::/root:/bin/sh\n\
        alice:x:1000:1000::/home/alice:/bin/sh\n\
        bob:x:1001:1001::/home/bob:/bin/sh\n\
        mallory:x:1003:1003::/home/mallory:/bin/sh\n";
    const START: u64 = 424242;

    struct FakeReauth {
        result: ReauthResult,
        calls: Mutex<Vec<String>>,
    }

    impl Reauth for FakeReauth {
        fn available(&self) -> bool {
            true
        }
        fn check(&self, _who: &Subject, detail: &str, _t: Duration) -> ReauthResult {
            self.calls.lock().unwrap().push(detail.to_string());
            self.result.clone()
        }
    }

    struct SteadyProc;
    impl Proc for SteadyProc {
        fn stat(&self, _pid: u32) -> Option<ProcStat> {
            Some(ProcStat {
                ppid: 1,
                comm: "saiife".into(),
                start_time: START,
            })
        }
        fn cmdline(&self, _pid: u32) -> Option<Vec<String>> {
            None
        }
    }

    struct Fx {
        ctx: Arc<Ctx>,
        reauth: Arc<FakeReauth>,
        dir: tempfile::TempDir,
        _join: std::thread::JoinHandle<()>,
    }

    /// A locked daemon (own uid 7) with `alice` the only approver; root is
    /// the admin.
    fn fx(same_user: &str, reauth: ReauthResult) -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let (mut ctx, join) = crate::ops::test_ctx(dir.path(), Mode::Locked, 7);
        let fake = Arc::new(FakeReauth {
            result: reauth,
            calls: Mutex::new(Vec::new()),
        });
        let c = Arc::get_mut(&mut ctx).unwrap();
        c.directory = Arc::new(saiife_policy::FixedDirectory::from_text(PASSWD, ""));
        c.reauth = fake.clone();
        c.proc = Box::new(SteadyProc);
        let cfg: saiife_policy::SystemConfig = toml::from_str(&format!(
            "version = 2\nlocked = true\n[approval]\napprovers = [\"alice\"]\n\
             same_user = \"{same_user}\"\n"
        ))
        .unwrap();
        *ctx.policy.lock().unwrap() = PolicyState {
            system: Some(Arc::new(cfg)),
            ..PolicyState::invalid(0)
        };
        Fx {
            ctx,
            reauth: fake,
            dir,
            _join: join,
        }
    }

    fn conn(uid: u32) -> Conn {
        Conn::new(
            PeerCred {
                uid,
                gid: uid,
                pid: 4242,
                sid: None,
                group_sids: Vec::new(),
            },
            Some(START),
        )
    }

    fn req(op: &str, args: Value) -> Request {
        Request {
            id: 1,
            op: op.into(),
            args: args.as_object().unwrap().clone(),
        }
    }

    async fn call(f: &Fx, uid: u32, op: &str, args: Value) -> Value {
        handle(&f.ctx, &conn(uid), req(op, args)).await
    }

    const ADMIN: u32 = 0;
    const ALICE: u32 = 1000;
    const BOB: u32 = 1001;
    const MALLORY: u32 = 1003;

    /// The device side of a pairing, against the offer `begin` answered.
    fn device_request(begin: &Value, d: &TestDevice, label: &str) -> PairRequest {
        let (pair_id, secret, _, _) =
            pair::parse_fragment(begin["fragment"].as_str().unwrap()).unwrap();
        let pubkey = d.public_raw();
        PairRequest {
            pair_id: pair_id.clone(),
            device_pub: b64::enc(&pubkey),
            label: label.into(),
            proof: b64::enc(&proof(&secret, &pair_id, &pubkey)),
            passkey: None,
        }
    }

    fn finish(f: &Fx, begin: &Value, d: &TestDevice) -> String {
        let now = crate::workspace::now_secs();
        let (_, code) = f
            .ctx
            .workspace
            .finish_pair(&device_request(begin, d, "phone"), now)
            .unwrap();
        code
    }

    fn audit_text(f: &Fx) -> String {
        fn walk(p: &std::path::Path, out: &mut String) {
            for e in std::fs::read_dir(p).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if let Ok(t) = std::fs::read_to_string(&p) {
                    out.push_str(&t);
                }
            }
        }
        let mut s = String::new();
        walk(&f.dir.path().join("audit"), &mut s);
        s
    }

    #[tokio::test]
    async fn admin_pairs_without_reauth() {
        let f = fx("deny", ReauthResult::Denied(String::new()));
        let b = call(
            &f,
            ADMIN,
            OP_WORKSPACE_PAIR_BEGIN,
            json!({"label": "my phone"}),
        )
        .await;
        assert_eq!(b["ok"], true, "{b}");
        assert!(b["fragment"].as_str().is_some_and(|s| !s.is_empty()));
        assert_eq!(b["machine_id"], f.ctx.workspace.machine_id());
        let d = TestDevice::generate();
        finish(&f, &b, &d);
        let c = call(
            &f,
            ADMIN,
            OP_WORKSPACE_PAIR_CONFIRM,
            json!({"pair_id": b["pair_id"], "accept": true}),
        )
        .await;
        assert_eq!(c["ok"], true, "{c}");
        assert_eq!(c["state"], "active");
        assert_eq!(c["device_id"], d.device_id());
        assert!(f.reauth.calls.lock().unwrap().is_empty());
        let list = call(&f, ADMIN, OP_WORKSPACE_DEVICES, json!({})).await;
        let devs = list["devices"].as_array().unwrap();
        assert_eq!(devs.len(), 1);
        assert!(devs[0].get("public_key").is_none(), "{list}");
        assert_eq!(devs[0]["owner_user"], "root");
        assert_eq!(devs[0]["state"], "active");
        let text = audit_text(&f);
        assert!(
            text.contains("pair_offer") && text.contains("paired"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn approver_needs_reauth_to_pair() {
        // same_user = "deny": the approver confirms its own request, refused.
        let f = fx("deny", ReauthResult::Authorized);
        let b = call(&f, ALICE, OP_WORKSPACE_PAIR_BEGIN, json!({})).await;
        assert_eq!(b["ok"], true, "begin needs no reauth: {b}");
        finish(&f, &b, &TestDevice::generate());
        let c = call(
            &f,
            ALICE,
            OP_WORKSPACE_PAIR_CONFIRM,
            json!({"pair_id": b["pair_id"], "accept": true}),
        )
        .await;
        assert_eq!(c["ok"], false, "{c}");
        assert!(
            c["message"]
                .as_str()
                .unwrap()
                .contains("refused (reauth_required)"),
            "{c}"
        );
        assert!(f.ctx.workspace.devices().is_empty());
        assert!(audit_text(&f).contains("reauth_required"));

        // same_user = "reauth", the person says no: refused, nothing paired.
        let f = fx("reauth", ReauthResult::Denied("no".into()));
        let b = call(&f, ALICE, OP_WORKSPACE_PAIR_BEGIN, json!({})).await;
        finish(&f, &b, &TestDevice::generate());
        let c = call(
            &f,
            ALICE,
            OP_WORKSPACE_PAIR_CONFIRM,
            json!({"pair_id": b["pair_id"], "accept": true}),
        )
        .await;
        assert_eq!(c["ok"], false, "{c}");
        assert!(f.ctx.workspace.devices().is_empty());

        // ... and yes: paired, and polkit was asked about PAIR_DETAIL.
        let f = fx("reauth", ReauthResult::Authorized);
        let b = call(&f, ALICE, OP_WORKSPACE_PAIR_BEGIN, json!({})).await;
        let d = TestDevice::generate();
        finish(&f, &b, &d);
        let c = call(
            &f,
            ALICE,
            OP_WORKSPACE_PAIR_CONFIRM,
            json!({"pair_id": b["pair_id"], "accept": true}),
        )
        .await;
        assert_eq!(c["ok"], true, "{c}");
        assert_eq!(f.reauth.calls.lock().unwrap().as_slice(), [PAIR_DETAIL]);
        assert_eq!(f.ctx.workspace.devices().len(), 1);
    }

    #[tokio::test]
    async fn reject_needs_no_reauth_but_the_same_people() {
        let f = fx("deny", ReauthResult::Denied(String::new()));
        let b = call(&f, ALICE, OP_WORKSPACE_PAIR_BEGIN, json!({})).await;
        let d = TestDevice::generate();
        finish(&f, &b, &d);
        let c = call(
            &f,
            MALLORY,
            OP_WORKSPACE_PAIR_CONFIRM,
            json!({"pair_id": b["pair_id"], "accept": false}),
        )
        .await;
        assert_eq!(c["error"], "forbidden", "{c}");
        let c = call(
            &f,
            ALICE,
            OP_WORKSPACE_PAIR_CONFIRM,
            json!({"pair_id": b["pair_id"], "accept": false}),
        )
        .await;
        assert_eq!(c["ok"], true, "{c}");
        assert_eq!(c["state"], "rejected");
        assert!(f.reauth.calls.lock().unwrap().is_empty());
        assert!(f.ctx.workspace.devices().is_empty());
        assert!(audit_text(&f).contains("pair_rejected"));
    }

    #[tokio::test]
    async fn only_the_begin_user_or_an_admin_confirms() {
        let f = fx("reauth", ReauthResult::Authorized);
        // An approver that did not begin the offer cannot confirm it.
        let mut cfg = (*f.ctx.policy().system.unwrap()).clone();
        cfg.approval.approvers = vec!["alice".into(), "bob".into()];
        f.ctx.policy.lock().unwrap().system = Some(Arc::new(cfg));
        let b = call(&f, ALICE, OP_WORKSPACE_PAIR_BEGIN, json!({})).await;
        finish(&f, &b, &TestDevice::generate());
        let args = json!({"pair_id": b["pair_id"], "accept": true});
        let c = call(&f, BOB, OP_WORKSPACE_PAIR_CONFIRM, args.clone()).await;
        assert_eq!(c["error"], "forbidden", "{c}");
        assert!(f.reauth.calls.lock().unwrap().is_empty());
        let c = call(&f, ADMIN, OP_WORKSPACE_PAIR_CONFIRM, args).await;
        assert_eq!(c["ok"], true, "{c}");
        // The device belongs to the user who began the offer.
        assert_eq!(f.ctx.workspace.devices()[0].owner_user, "alice");
    }

    #[tokio::test]
    async fn non_approver_cannot_pair() {
        let f = fx("reauth", ReauthResult::Authorized);
        for op in [
            OP_WORKSPACE_PAIR_BEGIN,
            OP_WORKSPACE_PAIR_STATUS,
            OP_WORKSPACE_PAIR_CONFIRM,
            OP_WORKSPACE_DEVICES,
            OP_WORKSPACE_REVOKE,
        ] {
            let a = call(
                &f,
                MALLORY,
                op,
                json!({"pair_id": "x", "accept": true, "device_id": "d-x"}),
            )
            .await;
            assert_eq!(a["error"], "forbidden", "{op}: {a}");
        }
        let a = call(&f, MALLORY, OP_WORKSPACE_PAIR_BEGIN, json!({})).await;
        assert_eq!(a["ok"], false);
        assert!(f.reauth.calls.lock().unwrap().is_empty());
        assert!(audit_text(&f).contains("forbidden"));
    }

    #[tokio::test]
    async fn second_request_for_one_offer_is_refused() {
        let f = fx("deny", ReauthResult::Authorized);
        let b = call(&f, ADMIN, OP_WORKSPACE_PAIR_BEGIN, json!({})).await;
        finish(&f, &b, &TestDevice::generate());
        let now = crate::workspace::now_secs();
        let second = f
            .ctx
            .workspace
            .finish_pair(&device_request(&b, &TestDevice::generate(), "other"), now);
        assert!(second.is_err());
        // The first stays the one waiting.
        let s = call(
            &f,
            ADMIN,
            OP_WORKSPACE_PAIR_STATUS,
            json!({"pair_id": b["pair_id"]}),
        )
        .await;
        assert_eq!(s["state"], "requested", "{s}");
        assert_eq!(s["label"], "phone");
    }

    #[tokio::test]
    async fn status_is_for_the_begin_user() {
        let f = fx("deny", ReauthResult::Authorized);
        let mut cfg = (*f.ctx.policy().system.unwrap()).clone();
        cfg.approval.approvers = vec!["alice".into(), "bob".into()];
        f.ctx.policy.lock().unwrap().system = Some(Arc::new(cfg));
        let b = call(&f, ALICE, OP_WORKSPACE_PAIR_BEGIN, json!({})).await;
        let args = json!({"pair_id": b["pair_id"]});
        let s = call(&f, ALICE, OP_WORKSPACE_PAIR_STATUS, args.clone()).await;
        assert_eq!(s["ok"], true, "{s}");
        assert_eq!(s["state"], "waiting");
        let s = call(&f, BOB, OP_WORKSPACE_PAIR_STATUS, args.clone()).await;
        assert_eq!(s["error"], "forbidden", "{s}");
        let s = call(&f, ADMIN, OP_WORKSPACE_PAIR_STATUS, args).await;
        assert_eq!(s["error"], "forbidden", "{s}");
        let s = call(
            &f,
            ALICE,
            OP_WORKSPACE_PAIR_STATUS,
            json!({"pair_id": "nope"}),
        )
        .await;
        assert_eq!(s["state"], "expired", "{s}");
    }

    #[tokio::test]
    async fn records_never_hold_the_secret() {
        let f = fx("reauth", ReauthResult::Authorized);
        let b = call(&f, ADMIN, OP_WORKSPACE_PAIR_BEGIN, json!({"label": "x"})).await;
        let fragment = b["fragment"].as_str().unwrap().to_string();
        let (_, secret, _, _) = pair::parse_fragment(&fragment).unwrap();
        let d = TestDevice::generate();
        finish(&f, &b, &d);
        let args = json!({"pair_id": b["pair_id"], "accept": true});
        call(
            &f,
            ADMIN,
            OP_WORKSPACE_PAIR_STATUS,
            json!({"pair_id": b["pair_id"]}),
        )
        .await;
        let c = call(&f, ADMIN, OP_WORKSPACE_PAIR_CONFIRM, args).await;
        assert_eq!(c["ok"], true, "{c}");
        call(
            &f,
            ADMIN,
            OP_WORKSPACE_REVOKE,
            json!({"device_id": d.device_id()}),
        )
        .await;
        // A refused attempt writes a record too.
        call(&f, MALLORY, OP_WORKSPACE_PAIR_BEGIN, json!({})).await;
        let text = audit_text(&f);
        assert!(text.contains("pair_offer") && text.contains("revoked"));
        assert!(!text.contains(&fragment), "fragment in a record");
        assert!(!text.contains(&b64::enc(&secret)), "secret in a record");
        assert!(!text.contains("fragment"), "{text}");
    }

    #[tokio::test]
    async fn revoke_records_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = fx("deny", ReauthResult::Authorized);
        let (ws, w) = crate::workspace::Workspace::open(crate::workspace::dir_in(dir.path()));
        assert!(w.is_none());
        Arc::get_mut(&mut f.ctx).unwrap().workspace = Arc::new(ws);
        let b = call(&f, ADMIN, OP_WORKSPACE_PAIR_BEGIN, json!({})).await;
        let d = TestDevice::generate();
        finish(&f, &b, &d);
        call(
            &f,
            ADMIN,
            OP_WORKSPACE_PAIR_CONFIRM,
            json!({"pair_id": b["pair_id"], "accept": true}),
        )
        .await;
        // An approver under same_user = "deny" cannot revoke.
        let r = call(
            &f,
            ALICE,
            OP_WORKSPACE_REVOKE,
            json!({"device_id": d.device_id()}),
        )
        .await;
        assert_eq!(r["ok"], false, "{r}");
        assert!(
            r["message"].as_str().unwrap().contains("reauth_required"),
            "{r}"
        );
        let r = call(
            &f,
            ADMIN,
            OP_WORKSPACE_REVOKE,
            json!({"device_id": d.device_id()}),
        )
        .await;
        assert_eq!(r["ok"], true, "{r}");
        assert_eq!(r["state"], "revoked");
        assert_eq!(r["device_id"], d.device_id());
        let (again, _) = crate::workspace::Workspace::open(crate::workspace::dir_in(dir.path()));
        assert_eq!(
            again.device(&d.device_id()).unwrap().state,
            saiife_wire::device::DeviceState::Revoked
        );
        assert!(audit_text(&f).contains("\"revoked\""));
        // Unknown devices are an error, not a silent success.
        let r = call(
            &f,
            ADMIN,
            OP_WORKSPACE_REVOKE,
            json!({"device_id": "d-nope"}),
        )
        .await;
        assert_eq!(r["error"], "bad_request", "{r}");
    }

    #[tokio::test]
    async fn a_revoke_that_cannot_be_saved_says_so_and_still_records() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = fx("deny", ReauthResult::Authorized);
        let wdir = crate::workspace::dir_in(dir.path());
        let (ws, _) = crate::workspace::Workspace::open(wdir.clone());
        Arc::get_mut(&mut f.ctx).unwrap().workspace = Arc::new(ws);
        let b = call(&f, ADMIN, OP_WORKSPACE_PAIR_BEGIN, json!({})).await;
        let d = TestDevice::generate();
        finish(&f, &b, &d);
        call(
            &f,
            ADMIN,
            OP_WORKSPACE_PAIR_CONFIRM,
            json!({"pair_id": b["pair_id"], "accept": true}),
        )
        .await;
        std::fs::create_dir(wdir.join(format!(".{}.tmp", crate::workspace::DEVICES_FILE))).unwrap();
        let r = call(
            &f,
            ADMIN,
            OP_WORKSPACE_REVOKE,
            json!({"device_id": d.device_id()}),
        )
        .await;
        assert_eq!(r["ok"], false, "{r}");
        assert_eq!(r["error"], "internal");
        assert!(r["message"].as_str().unwrap().contains("NOT saved"), "{r}");
        let text = audit_text(&f);
        assert!(
            text.contains("\"revoked\"") && text.contains("not saved"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn bad_arguments_are_bad_requests() {
        let f = fx("deny", ReauthResult::Authorized);
        for (op, args) in [
            (OP_WORKSPACE_PAIR_BEGIN, json!({"label": 5})),
            (OP_WORKSPACE_PAIR_BEGIN, json!({"label": "a".repeat(41)})),
            (OP_WORKSPACE_PAIR_BEGIN, json!({"label": "a\nb"})),
            (OP_WORKSPACE_PAIR_STATUS, json!({})),
            (OP_WORKSPACE_PAIR_CONFIRM, json!({"pair_id": "x"})),
            (
                OP_WORKSPACE_PAIR_CONFIRM,
                json!({"pair_id": "x", "accept": true, "auth": 5}),
            ),
            (OP_WORKSPACE_REVOKE, json!({})),
        ] {
            let a = call(&f, ADMIN, op, args.clone()).await;
            assert_eq!(a["error"], "bad_request", "{op} {args}: {a}");
        }
        // Nothing waiting: a bad request before any prompt.
        let a = call(
            &f,
            ADMIN,
            OP_WORKSPACE_PAIR_CONFIRM,
            json!({"pair_id": "x", "accept": true}),
        )
        .await;
        assert_eq!(a["error"], "bad_request", "{a}");
    }

    /// Re-authentication that takes `secs` of the Workspace clock.
    struct SlowReauth {
        clock: Arc<std::sync::atomic::AtomicU64>,
        secs: u64,
    }

    impl Reauth for SlowReauth {
        fn available(&self) -> bool {
            true
        }
        fn check(&self, _who: &Subject, _detail: &str, _t: Duration) -> ReauthResult {
            self.clock
                .fetch_add(self.secs, std::sync::atomic::Ordering::SeqCst);
            ReauthResult::Authorized
        }
    }

    #[tokio::test]
    async fn an_offer_that_expires_during_the_prompt_is_refused() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let mut f = fx("reauth", ReauthResult::Authorized);
        let clock = Arc::new(AtomicU64::new(1_900_000_000));
        let c2 = Arc::clone(&clock);
        {
            let c = Arc::get_mut(&mut f.ctx).unwrap();
            c.workspace = Arc::new(
                crate::workspace::Workspace::memory()
                    .with_clock(Arc::new(move || c2.load(Ordering::SeqCst))),
            );
            c.reauth = Arc::new(SlowReauth {
                clock: Arc::clone(&clock),
                secs: pair::OFFER_TTL_SECS + 1,
            });
        }
        let b = call(&f, ALICE, OP_WORKSPACE_PAIR_BEGIN, json!({})).await;
        let d = TestDevice::generate();
        f.ctx
            .workspace
            .finish_pair(
                &device_request(&b, &d, "phone"),
                clock.load(Ordering::SeqCst),
            )
            .unwrap();
        let c = call(
            &f,
            ALICE,
            OP_WORKSPACE_PAIR_CONFIRM,
            json!({"pair_id": b["pair_id"], "accept": true}),
        )
        .await;
        assert_eq!(c["ok"], false, "{c}");
        assert!(c["message"].as_str().unwrap().contains("lapsed"), "{c}");
        assert!(f.ctx.workspace.devices().is_empty());
    }

    #[tokio::test]
    async fn confirm_on_a_locked_workspace_says_locked() {
        use std::os::unix::fs::PermissionsExt;
        let mut f = fx("deny", ReauthResult::Authorized);
        let wdir = crate::workspace::dir_in(f.dir.path());
        std::fs::create_dir_all(&wdir).unwrap();
        let key = wdir.join(crate::workspace::KEY_FILE);
        std::fs::write(&key, b"not a key").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let (ws, w) = crate::workspace::Workspace::open(wdir);
        assert!(w.is_some());
        Arc::get_mut(&mut f.ctx).unwrap().workspace = Arc::new(ws);
        let c = call(
            &f,
            ADMIN,
            OP_WORKSPACE_PAIR_CONFIRM,
            json!({"pair_id": "x", "accept": true}),
        )
        .await;
        assert_eq!(c["error"], "unavailable", "{c}");
        assert_eq!(c["rule"], "workspace_locked", "{c}");
        assert!(audit_text(&f).contains("workspace_locked"));
    }

    #[tokio::test]
    async fn revoking_a_revoked_device_needs_no_prompt() {
        let f = fx("reauth", ReauthResult::Authorized);
        let b = call(&f, ADMIN, OP_WORKSPACE_PAIR_BEGIN, json!({})).await;
        let d = TestDevice::generate();
        finish(&f, &b, &d);
        call(
            &f,
            ADMIN,
            OP_WORKSPACE_PAIR_CONFIRM,
            json!({"pair_id": b["pair_id"], "accept": true}),
        )
        .await;
        let args = json!({"device_id": d.device_id()});
        let r = call(&f, ADMIN, OP_WORKSPACE_REVOKE, args.clone()).await;
        assert_eq!(r["ok"], true, "{r}");
        // An approver revoking it again: nothing to grant, no prompt.
        let r = call(&f, ALICE, OP_WORKSPACE_REVOKE, args).await;
        assert_eq!(r["ok"], true, "{r}");
        assert_eq!(r["state"], "revoked");
        assert!(f.reauth.calls.lock().unwrap().is_empty());
    }

    // ---- passkey enrolment (plan 31) ----

    const ORIGIN: &str = "http://localhost:47810";

    struct Pk {
        args: Value,
        id: Vec<u8>,
    }

    /// The browser side: a create-side authData with AT from the soft
    /// authenticator, a clientDataJSON, and the device key's signature.
    /// `tweak` edits (challenge, origin, type, authData) before signing.
    fn passkey_req(
        begin: &Value,
        d: &TestDevice,
        signer: &TestDevice,
        tweak: &dyn Fn(&mut String, &mut String, &mut Vec<u8>),
    ) -> Pk {
        use saiife_touch::{EnrolRequest, Touch};
        let (pair_id, secret, _, _) =
            pair::parse_fragment(begin["fragment"].as_str().unwrap()).unwrap();
        let pubkey = d.public_raw();
        let auth = saiife_touch::soft::SoftAuthenticator::new_es256();
        let mut ad = auth
            .enrol(&EnrolRequest {
                rp_id: "localhost".into(),
                rp_name: "saiife".into(),
                user_id: vec![1],
                user_name: "phone".into(),
                challenge: [0; 32],
                exclude: vec![],
            })
            .unwrap();
        let mut challenge = b64::enc(&pair::passkey_challenge(&pair_id, &pubkey));
        let mut origin = ORIGIN.to_string();
        tweak(&mut challenge, &mut origin, &mut ad);
        let cdj = format!(
            "{{\"type\":\"webauthn.create\",\"challenge\":\"{challenge}\",\"origin\":\"{origin}\",\"crossOrigin\":false}}"
        );
        let mut att = pair::PasskeyAttestation {
            credential_id: b64::enc(&auth.credential_id()),
            authenticator_data: b64::enc(&ad),
            client_data_json: b64::enc(cdj.as_bytes()),
            device_sig: String::new(),
        };
        let msg = pair::passkey_sig_msg(&pair_id, &att).unwrap();
        att.device_sig = b64::enc(&signer.sign_domain(pair::PASSKEY_DOMAIN, &msg));
        let args = json!({
            "pair_id": pair_id,
            "device_pub": b64::enc(&pubkey),
            "label": "phone",
            "proof": b64::enc(&proof(&secret, &pair_id, &pubkey)),
            "passkey": att,
        });
        Pk {
            args,
            id: auth.credential_id(),
        }
    }

    async fn link_finish(f: &Fx, args: Value) -> Value {
        crate::workspace_link::dispatch_link(
            &f.ctx,
            &conn(ALICE),
            req(saiife_ipc::msg::OP_WORKSPACE_PAIR_FINISH, args),
        )
        .await
    }

    async fn begin(f: &Fx) -> Value {
        let b = call(f, ADMIN, OP_WORKSPACE_PAIR_BEGIN, json!({})).await;
        assert_eq!(b["ok"], true, "{b}");
        b
    }

    async fn confirm_accept(f: &Fx, b: &Value) -> Value {
        call(
            f,
            ADMIN,
            OP_WORKSPACE_PAIR_CONFIRM,
            json!({"pair_id": b["pair_id"], "accept": true}),
        )
        .await
    }

    /// The refused request leaves the offer open and nothing stored.
    async fn refused_whole(f: &Fx, b: &Value, pk: Pk) {
        let r = link_finish(f, pk.args).await;
        assert_eq!(r["ok"], false, "{r}");
        assert_eq!(r["rule"], "passkey_refused", "{r}");
        let s = call(
            f,
            ADMIN,
            OP_WORKSPACE_PAIR_STATUS,
            json!({"pair_id": b["pair_id"]}),
        )
        .await;
        assert_eq!(s["state"], "waiting", "{s}");
        assert!(f.ctx.touch.credentials_of(0).is_empty());
    }

    #[tokio::test]
    async fn pair_with_passkey_enrols_credential() {
        let f = fx("deny", ReauthResult::Authorized);
        let b = begin(&f).await;
        let d = TestDevice::generate();
        let pk = passkey_req(&b, &d, &d, &|_, _, _| {});
        let r = link_finish(&f, pk.args.clone()).await;
        assert_eq!(r["ok"], true, "{r}");
        // Held, not stored, until the machine confirms.
        assert!(f.ctx.touch.credentials_of(0).is_empty());
        let c = confirm_accept(&f, &b).await;
        assert_eq!(c["ok"], true, "{c}");
        assert_eq!(c["passkey"], b64::enc(&pk.id), "{c}");
        let creds = f.ctx.touch.credentials_of(0);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].kind, "webauthn");
        assert_eq!(creds[0].rp_id, "localhost");
        assert_eq!(creds[0].origins, vec![ORIGIN.to_string()]);
        assert_eq!(creds[0].id, pk.id);
        let devs = f.ctx.workspace.devices();
        assert_eq!(devs[0].touch_credentials, vec![b64::enc(&pk.id)]);
        assert!(audit_text(&f).contains(&b64::enc(&pk.id)));
    }

    #[tokio::test]
    async fn passkey_with_wrong_challenge_is_refused() {
        let f = fx("deny", ReauthResult::Authorized);
        let b = begin(&f).await;
        let d = TestDevice::generate();
        let pk = passkey_req(&b, &d, &d, &|c, _, _| *c = b64::enc(&[7u8; 32]));
        refused_whole(&f, &b, pk).await;
    }

    #[tokio::test]
    async fn passkey_signed_by_another_key_is_refused() {
        let f = fx("deny", ReauthResult::Authorized);
        let b = begin(&f).await;
        let d = TestDevice::generate();
        let other = TestDevice::generate();
        let pk = passkey_req(&b, &d, &other, &|_, _, _| {});
        refused_whole(&f, &b, pk).await;
    }

    #[tokio::test]
    async fn passkey_without_uv_is_refused() {
        let f = fx("deny", ReauthResult::Authorized);
        let b = begin(&f).await;
        let d = TestDevice::generate();
        // Flags byte: UP | AT, no UV.
        let pk = passkey_req(&b, &d, &d, &|_, _, ad| ad[32] = 0x41);
        refused_whole(&f, &b, pk).await;
    }

    #[tokio::test]
    async fn passkey_for_other_origin_is_refused() {
        let f = fx("deny", ReauthResult::Authorized);
        let b = begin(&f).await;
        let d = TestDevice::generate();
        let pk = passkey_req(&b, &d, &d, &|_, o, _| *o = "http://localhost:9".into());
        refused_whole(&f, &b, pk).await;
    }

    #[tokio::test]
    async fn pair_without_passkey_is_signed_only() {
        let f = fx("deny", ReauthResult::Authorized);
        let b = begin(&f).await;
        let d = TestDevice::generate();
        finish(&f, &b, &d);
        let c = confirm_accept(&f, &b).await;
        assert_eq!(c["ok"], true, "{c}");
        assert!(c.get("passkey").is_none(), "{c}");
        assert!(f.ctx.touch.credentials_of(0).is_empty());
        assert!(f.ctx.workspace.devices()[0].touch_credentials.is_empty());
    }

    #[tokio::test]
    async fn reject_stores_no_credential() {
        let f = fx("deny", ReauthResult::Authorized);
        let b = begin(&f).await;
        let d = TestDevice::generate();
        let pk = passkey_req(&b, &d, &d, &|_, _, _| {});
        assert_eq!(link_finish(&f, pk.args).await["ok"], true);
        let c = call(
            &f,
            ADMIN,
            OP_WORKSPACE_PAIR_CONFIRM,
            json!({"pair_id": b["pair_id"], "accept": false}),
        )
        .await;
        assert_eq!(c["state"], "rejected", "{c}");
        assert!(f.ctx.touch.credentials_of(0).is_empty());
        assert!(f.ctx.touch.all().is_empty());
        assert!(f.ctx.workspace.devices().is_empty());
    }

    #[tokio::test]
    async fn wrong_proof_with_passkey_does_not_burn_the_offer() {
        let f = fx("deny", ReauthResult::Authorized);
        let b = begin(&f).await;
        let d = TestDevice::generate();
        let mut pk = passkey_req(&b, &d, &d, &|_, _, _| {});
        let good = pk.args["proof"].clone();
        pk.args["proof"] = json!(b64::enc(&[0u8; 32]));
        let r = link_finish(&f, pk.args.clone()).await;
        assert_eq!(r["ok"], false, "{r}");
        pk.args["proof"] = good;
        let r = link_finish(&f, pk.args).await;
        assert_eq!(r["ok"], true, "{r}");
        assert!(f.ctx.touch.all().is_empty());
    }

    #[tokio::test]
    async fn passkey_store_full_pairs_without_passkey() {
        let f = fx("deny", ReauthResult::Authorized);
        for i in 0..16u8 {
            let mut c =
                saiife_touch::soft::SoftAuthenticator::new_es256().credential("localhost", 0, "x");
            c.id = vec![i + 1; 16];
            f.ctx.touch.add(c).unwrap();
        }
        let b = begin(&f).await;
        let d = TestDevice::generate();
        let pk = passkey_req(&b, &d, &d, &|_, _, _| {});
        assert_eq!(link_finish(&f, pk.args).await["ok"], true);
        let c = confirm_accept(&f, &b).await;
        assert_eq!(c["ok"], true, "{c}");
        assert_eq!(c["state"], "active");
        assert_eq!(c["passkey"], "not_saved", "{c}");
        assert!(c["passkey_reason"].as_str().is_some(), "{c}");
        assert_eq!(f.ctx.touch.credentials_of(0).len(), 16);
        let devs = f.ctx.workspace.devices();
        assert_eq!(devs[0].state, saiife_wire::device::DeviceState::Active);
        assert!(devs[0].touch_credentials.is_empty());
    }

    /// Pairs `d` with a passkey and confirms; returns the credential id.
    async fn paired_with_passkey(f: &Fx, d: &TestDevice) -> (Value, Vec<u8>) {
        let b = begin(f).await;
        let pk = passkey_req(&b, d, d, &|_, _, _| {});
        assert_eq!(link_finish(f, pk.args).await["ok"], true);
        let c = confirm_accept(f, &b).await;
        assert_eq!(c["ok"], true, "{c}");
        assert_eq!(c["passkey"], b64::enc(&pk.id), "{c}");
        (b, pk.id)
    }

    #[tokio::test]
    async fn revoke_removes_the_passkey_and_audits_it() {
        let f = fx("deny", ReauthResult::Authorized);
        let d = TestDevice::generate();
        let (_, cid) = paired_with_passkey(&f, &d).await;
        assert_eq!(f.ctx.touch.credentials_of(0).len(), 1);
        let r = call(
            &f,
            ADMIN,
            OP_WORKSPACE_REVOKE,
            json!({"device_id": d.device_id()}),
        )
        .await;
        assert_eq!(r["ok"], true, "{r}");
        assert!(f.ctx.touch.credentials_of(0).is_empty());
        assert!(f.ctx.touch.all().is_empty());
        let text = audit_text(&f);
        let line = text
            .lines()
            .find(|l| l.contains("touch_removed"))
            .unwrap_or_else(|| panic!("no touch_removed record: {text}"));
        assert!(line.contains(&d.device_id()), "{line}");
        assert!(line.contains(&b64::enc(&cid)), "{line}");
    }

    #[tokio::test]
    async fn revoke_with_a_removal_failure_still_revokes_and_audits_it() {
        use std::os::unix::fs::PermissionsExt;
        if rustix::process::geteuid().as_raw() == 0 {
            return; // root writes through a read-only directory
        }
        let f = fx("deny", ReauthResult::Authorized);
        let d = TestDevice::generate();
        let (_, cid) = paired_with_passkey(&f, &d).await;
        let touch_dir = f.dir.path().join("state").join("state").join("touch");
        std::fs::set_permissions(&touch_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let r = call(
            &f,
            ADMIN,
            OP_WORKSPACE_REVOKE,
            json!({"device_id": d.device_id()}),
        )
        .await;
        std::fs::set_permissions(&touch_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(r["ok"], true, "{r}");
        assert_eq!(
            f.ctx.workspace.device(&d.device_id()).unwrap().state,
            saiife_wire::device::DeviceState::Revoked
        );
        // The credential is still there (fail closed on the revoke, not on the store).
        assert_eq!(f.ctx.touch.credentials_of(0).len(), 1);
        let text = audit_text(&f);
        let line = text
            .lines()
            .find(|l| l.contains("touch_removed"))
            .unwrap_or_else(|| panic!("no touch_removed record: {text}"));
        assert!(line.contains("touch_not_removed"), "{line}");
        assert!(line.contains(&d.device_id()), "{line}");
        assert!(line.contains(&b64::enc(&cid)), "{line}");
        // A repeated revoke retries the removal.
        let r = call(
            &f,
            ADMIN,
            OP_WORKSPACE_REVOKE,
            json!({"device_id": d.device_id()}),
        )
        .await;
        assert_eq!(r["ok"], true, "{r}");
        assert!(f.ctx.touch.credentials_of(0).is_empty());
    }

    #[tokio::test]
    async fn revoked_device_cannot_pair_again_with_a_passkey() {
        let f = fx("deny", ReauthResult::Authorized);
        let d = TestDevice::generate();
        paired_with_passkey(&f, &d).await;
        let r = call(
            &f,
            ADMIN,
            OP_WORKSPACE_REVOKE,
            json!({"device_id": d.device_id()}),
        )
        .await;
        assert_eq!(r["ok"], true, "{r}");
        let b = begin(&f).await;
        let pk = passkey_req(&b, &d, &d, &|_, _, _| {});
        let r = link_finish(&f, pk.args).await;
        assert_eq!(r["ok"], false, "{r}");
        let c = confirm_accept(&f, &b).await;
        assert_eq!(c["ok"], false, "{c}");
        assert!(f.ctx.touch.credentials_of(0).is_empty());
        assert_eq!(
            f.ctx.workspace.device(&d.device_id()).unwrap().state,
            saiife_wire::device::DeviceState::Revoked
        );
    }
}
