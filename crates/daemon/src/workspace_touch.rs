//! Workspace touches (plan 31): the origin list and the web assertion.
//!
//! The browser and the hub are untrusted: the origin an assertion was made
//! for is read from its own `clientDataJSON` (which `verify` binds to the
//! signature) and must be one the machine's config lists. The RP id is
//! derived from the configured origin, never from the browser.

use crate::ops::Ctx;
use crate::touch::IssueKey;
use crate::workspace_link::{
    blocking, id_arg, invalid, only, str_arg, text_arg, uid_of, Fail, Refused,
};
use saiife_ipc::msg::ErrorCode;
use saiife_touch::{
    challenge, short_code, ActionRecord, Assertion, Credential, TouchClass, TouchError,
    TouchEvidence, TouchRequest,
};
use saiife_wire::device::DeviceState;
use saiife_wire::frame::TouchProof;
use saiife_wire::level::{actions as a, spawn_level, Level};
use saiife_wire::pair::{passkey_challenge, passkey_sig_msg, PasskeyAttestation, PASSKEY_DOMAIN};
use saiife_wire::sig::verify_p256_domain;
use saiife_wire::source::PendingAction;
use saiife_wire::source::{BoxId, BoxSource, MAX_TASK_BYTES};
use saiife_wire::verify::Verified;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

/// How long a touch on a box keeps that box's steer actions open, in seconds.
pub const STEER_WINDOW_SECS: u64 = 600;
/// The longest template or repo name a bound spawn takes.
const MAX_NAME_BYTES: usize = 256;
/// The longest summary the browser is shown.
const MAX_SUMMARY: usize = 200;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The Workspace's web touches: the next request id, challenges already
/// spent (so one assertion is never used twice), and the steer windows a
/// touch opened, per (device, box), each with its expiry.
pub struct WebTouches {
    next: AtomicU64,
    spent: Mutex<BTreeMap<[u8; 32], u64>>,
    windows: Mutex<BTreeMap<(String, BoxId), u64>>,
}

impl Default for WebTouches {
    fn default() -> Self {
        WebTouches::new()
    }
}

impl WebTouches {
    pub fn new() -> WebTouches {
        WebTouches {
            next: AtomicU64::new(1),
            spent: Mutex::new(BTreeMap::new()),
            windows: Mutex::new(BTreeMap::new()),
        }
    }

    /// The next request id (from 1, never repeated within a run).
    pub fn next_id(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed)
    }

    /// Marks `challenge` spent until `expires_at`. False when it already was
    /// (and not yet expired). Expired entries are dropped first.
    pub fn spend(&self, challenge: &[u8; 32], expires_at: u64, now: u64) -> bool {
        let mut m = lock(&self.spent);
        m.retain(|_, e| *e >= now);
        if m.contains_key(challenge) {
            return false;
        }
        m.insert(*challenge, expires_at);
        true
    }

    /// Opens (or renews) the steer window of `device` on box `id`.
    pub fn open_window(&self, device: &str, id: &BoxId, now: u64) {
        let mut m = lock(&self.windows);
        m.retain(|_, e| *e > now);
        m.insert(
            (device.to_string(), id.clone()),
            now.saturating_add(STEER_WINDOW_SECS),
        );
    }

    /// Whether `device` has an unexpired window on box `id`.
    pub fn window_open(&self, device: &str, id: &BoxId, now: u64) -> bool {
        lock(&self.windows)
            .get(&(device.to_string(), id.clone()))
            .is_some_and(|e| *e > now)
    }

    /// Closes every window of `device` (revoke).
    pub fn close_device(&self, device: &str) {
        lock(&self.windows).retain(|(d, _), _| d != device);
    }
}

fn refused(f: Fail) -> Refused {
    match f {
        Fail::Policy(r) | Fail::Source(r) => r,
    }
}

fn not_found(what: &str) -> Fail {
    Fail::Policy(Refused::new(
        ErrorCode::BadRequest,
        "not_found",
        format!("no such {what}"),
    ))
}

/// The class, summary and fields the daemon binds for a Touch action, from
/// its own view: nothing is taken from `args` beyond ids and the spawn's
/// own parameters, and any other key is `invalid`. `src` is the frame's
/// owner-scoped box source, `owner_uid` the device owner.
pub async fn bind(
    ctx: &Arc<Ctx>,
    owner_uid: u32,
    owner_user: &str,
    src: &Arc<dyn BoxSource>,
    action: &str,
    args: &Map<String, Value>,
) -> Result<(TouchClass, String, BTreeMap<String, String>), Refused> {
    bind_inner(ctx, owner_uid, owner_user, src, action, args)
        .await
        .map_err(refused)
}

async fn bind_inner(
    ctx: &Arc<Ctx>,
    owner_uid: u32,
    owner_user: &str,
    src: &Arc<dyn BoxSource>,
    action: &str,
    args: &Map<String, Value>,
) -> Result<(TouchClass, String, BTreeMap<String, String>), Fail> {
    let mut f: BTreeMap<String, String> = BTreeMap::new();
    f.insert("action".into(), action.into());
    match action {
        a::BOX_STEER | a::BOX_REVISE | a::BOX_RESUME => {
            only(args, &["id"])?;
            let id = id_arg(args)?;
            let list = blocking(src, |b| Ok(b.list())).await?;
            if !list.iter().any(|b| b.id == id) {
                return Err(not_found("box"));
            }
            f.insert("box".into(), id.as_str().into());
            Ok((
                TouchClass::Steer,
                format!("{action} box {}", id.as_str()),
                f,
            ))
        }
        a::BOX_SPAWN => {
            only(args, &["template", "repo", "task", "start"])?;
            let template = text_arg(args, "template", MAX_NAME_BYTES)?;
            let repo = text_arg(args, "repo", MAX_NAME_BYTES)?;
            let task = text_arg(args, "task", MAX_TASK_BYTES)?;
            let start = match args.get("start").and_then(Value::as_str) {
                Some(s @ ("now" | "queue")) => s,
                _ => return Err(invalid("start is \"now\" or \"queue\"")),
            };
            // The summary is plain text the browser shows: no control
            // characters at all (a newline would pass `check_text`).
            if template.chars().chain(repo.chars()).any(char::is_control) {
                return Err(invalid("template and repo are single-line text"));
            }
            let templates = blocking(src, |b| Ok(b.templates())).await?;
            let Some(t) = templates.iter().find(|t| t.name == template) else {
                return Err(invalid(format!("no template {template:?}")));
            };
            if spawn_level(t) != Level::Touch {
                return Err(invalid(format!(
                    "{template} needs no touch: spawn it with a signed frame"
                )));
            }
            let class = TouchClass::stronger(
                t.has_secrets.then_some(TouchClass::SecretSensitive),
                t.has_egress.then_some(TouchClass::EgressExternal),
            )
            .unwrap_or(TouchClass::SecretSensitive);
            let summary = format!("spawn {template} on {repo}");
            if summary.len() > MAX_SUMMARY {
                return Err(invalid("template and repo are too long to show"));
            }
            f.insert("template".into(), template.into());
            f.insert("repo".into(), repo.into());
            let digest: [u8; 32] = Sha256::digest(task.as_bytes()).into();
            f.insert("task_sha256".into(), crate::grants::hex(&digest));
            f.insert("start".into(), start.into());
            Ok((class, summary, f))
        }
        a::APPROVAL_APPROVE => {
            only(args, &["id"])?;
            let rid = args
                .get("id")
                .and_then(Value::as_u64)
                .ok_or_else(|| invalid("id is a request number"))?;
            let r = pending_request(ctx, owner_uid, owner_user, rid).await?;
            let class = crate::approval_ops::effective_class(ctx, &r)
                .ok_or_else(|| invalid(format!("request #{rid} needs no touch")))?;
            let rec = crate::approvals::action_record(&r, class, [0; 16], [0; 32], 0);
            Ok((class, rec.summary, rec.fields))
        }
        a::BOX_LAND => Err(invalid(
            "use the request id from the inbox: box.land is touched through its own request",
        )),
        other => Err(invalid(format!("{other} cannot be begun as a touch"))),
    }
}

/// Pending approval request `rid`, when the device owner may decide it: the
/// shared identity checks (`approval_ops::owner_may_decide`, the CLI's
/// own) run before any touch is issued or spent.
async fn pending_request(
    ctx: &Arc<Ctx>,
    owner_uid: u32,
    owner_user: &str,
    rid: u64,
) -> Result<crate::approvals::Request, Fail> {
    use crate::approval_ops::ApprovalLookup;
    match crate::approval_ops::request_to_approve(ctx, owner_uid, owner_user, rid).await {
        Err(ApprovalLookup::Unavailable) => Err(Fail::Policy(Refused::new(
            ErrorCode::Unavailable,
            "unavailable",
            "approvals are not available on this machine",
        ))),
        Err(ApprovalLookup::Unknown) => Err(not_found("approval request")),
        Err(ApprovalLookup::NotPending) => Err(invalid(format!("request #{rid} is not pending"))),
        Ok(Err(why)) => Err(Fail::Policy(Refused::new(
            ErrorCode::Forbidden,
            why.rule(),
            format!("request #{rid} cannot be approved by this user: {why}"),
        ))),
        Ok(Ok(r)) => Ok(r),
    }
}

/// The device's passkeys (`held`, its `touch_credentials`) that the owner's
/// touch store still holds, for one RP id (the first one's): what `begin`
/// allows, and what `workspace.whoami` lists so the page learns from the
/// daemon whether it can touch.
pub(crate) async fn device_passkeys(
    ctx: &Arc<Ctx>,
    owner_uid: u32,
    held: Vec<String>,
) -> Result<Vec<Credential>, Refused> {
    let c = Arc::clone(ctx);
    let creds: Vec<Credential> =
        tokio::task::spawn_blocking(move || c.touch.credentials_of(owner_uid))
            .await
            .map_err(|e| Refused::new(ErrorCode::Internal, "internal", e.to_string()))?
            .into_iter()
            .filter(|c| c.kind == "webauthn" && held.contains(&saiife_wire::b64::enc(&c.id)))
            .collect();
    let Some(rp_id) = creds.first().map(|c| c.rp_id.clone()) else {
        return Ok(Vec::new());
    };
    Ok(creds.into_iter().filter(|c| c.rp_id == rp_id).collect())
}

/// `workspace.touch.begin {action, args}`: issues a challenge bound to the
/// action as the daemon sees it, for the device's own passkey. The answer is
/// a `TouchRequest` plus `request_id`, `expires_at` and `class`.
pub(crate) async fn begin(ctx: &Arc<Ctx>, v: &Verified) -> Result<Value, Refused> {
    let args = &v.frame.args;
    only(args, &["action", "args"]).map_err(refused)?;
    let action = str_arg(args, "action").map_err(refused)?.to_string();
    let inner = match args.get("args") {
        Some(Value::Object(m)) => m.clone(),
        _ => return Err(refused(invalid("args is an object"))),
    };
    let Some(owner_uid) = uid_of(ctx, &v.owner_user).await else {
        return Err(Refused::new(
            ErrorCode::Forbidden,
            "unknown_owner",
            "the device owner is not a user of this machine",
        ));
    };
    let Some(device) = ctx.workspace.device(&v.device_id) else {
        return Err(Refused::new(
            ErrorCode::Forbidden,
            "unknown_device",
            "this device is no longer paired",
        ));
    };
    // The box source scoped to the device owner, as the action itself would
    // use it (a bound box must be one the owner may touch).
    let src = crate::workspace_link::source_for(ctx, v, &action, &inner)
        .await
        .map_err(refused)?;
    let (class, summary, fields) =
        bind(ctx, owner_uid, &v.owner_user, &src, &action, &inner).await?;
    let creds = device_passkeys(ctx, owner_uid, device.touch_credentials).await?;
    let Some(rp_id) = creds.first().map(|c| c.rp_id.clone()) else {
        return Err(Refused::new(
            ErrorCode::Unavailable,
            "touch_unavailable",
            "this browser has no passkey: pair it again to add one",
        ));
    };
    let allow: Vec<Vec<u8>> = creds.into_iter().map(|c| c.id).collect();
    let request_id = ctx.web_touch.next_id();
    // An approval's record carries the approval's own id (what the machine
    // prompt would show); every other touch carries the web request id.
    let record_id = if action == a::APPROVAL_APPROVE {
        inner.get("id").and_then(Value::as_u64).unwrap_or(0)
    } else {
        request_id
    };
    let key = crate::touch::IssueKey::Web {
        device: v.device_id.clone(),
        request_id,
    };
    let c = Arc::clone(ctx);
    let issued = tokio::task::spawn_blocking(move || {
        let t = &c.touch;
        let i = t.issue(
            key,
            owner_uid,
            class,
            summary.clone(),
            fields.clone(),
            crate::touch::unix_now(),
        )?;
        Ok::<_, String>(ActionRecord {
            instance_id: t.instance_id(),
            request_id: record_id,
            class,
            summary,
            fields,
            nonce: i.nonce,
            expires_at: i.expires_at,
        })
    })
    .await
    .map_err(|e| Refused::new(ErrorCode::Internal, "internal", e.to_string()))?;
    let rec = issued.map_err(|e| Refused::new(ErrorCode::Busy, "busy", e))?;
    let ch = challenge(&rec);
    let tr = TouchRequest {
        rp_id,
        challenge: ch,
        allow,
        uv: true,
        summary: rec.summary.clone(),
        short_code: short_code(&ch),
    };
    let mut m = match serde_json::to_value(&tr) {
        Ok(Value::Object(m)) => m,
        _ => {
            return Err(Refused::new(
                ErrorCode::Internal,
                "internal",
                "cannot encode the touch request",
            ))
        }
    };
    m.insert("request_id".into(), request_id.to_string().into());
    m.insert("expires_at".into(), rec.expires_at.into());
    m.insert("class".into(), class.name().into());
    // What the audit record of this begin carries: the inner action and box
    // as the daemon bound them.
    let mut tb = json!({
        "request_id": request_id.to_string(),
        "class": class.name(),
        "action": action,
    });
    if let Some(b) = rec.fields.get("box") {
        tb["box"] = json!(b);
    }
    m.insert("touch_begin".into(), tb);
    Ok(json!(m))
}

/// A verified touch, by what it was for.
pub enum Proven {
    /// A touch the daemon issued for a steer, revise, resume or spawn
    /// (`workspace.touch.begin`): its record, which equals what `bind` builds
    /// for the frame.
    Web(TouchEvidence, ActionRecord),
    /// A touch for a pending action a box source created (`box.land`).
    Pending(TouchEvidence, PendingAction),
    /// A touch for a v2 approval request (its id).
    Approval(TouchEvidence, u64),
}

impl Proven {
    pub fn evidence(&self) -> &TouchEvidence {
        match self {
            Proven::Web(e, _) | Proven::Pending(e, _) | Proven::Approval(e, _) => e,
        }
    }
}

fn touch_refused(e: TouchError) -> Refused {
    let code = match e {
        TouchError::Unavailable => ErrorCode::Unavailable,
        _ => ErrorCode::Forbidden,
    };
    Refused::new(code, e.rule(), e.to_string())
}

fn mismatch(why: &str) -> Refused {
    Refused::new(ErrorCode::Forbidden, "touch_mismatch", why)
}

fn internal(e: impl std::fmt::Display) -> Refused {
    Refused::new(ErrorCode::Internal, "internal", e.to_string())
}

/// The `args` a steer-class touch binds: the box id only (the text of a
/// steer or a revise is not bound; the touch opens the box's window).
fn bound_args(action: &str, args: &Map<String, Value>) -> Map<String, Value> {
    if matches!(action, a::BOX_STEER | a::BOX_REVISE | a::BOX_RESUME) {
        let mut m = Map::new();
        if let Some(id) = args.get("id") {
            m.insert("id".into(), id.clone());
        }
        m
    } else {
        args.clone()
    }
}

/// Verifies the touch proof of a Touch frame, in order: the request id, the
/// web assertion (origin from the configured list), the credential (the
/// frame's own ACTIVE device holds it, and the device owner's touch store
/// does), then the action's own binding. `src` is the frame's owner-scoped
/// box source. The challenge entry is burned whatever the outcome.
///
/// `[approval] same_user` is not checked here: `approval_ops::decide_remote`
/// (Task 6) is the single site that decides who may approve a request.
pub async fn verify_frame(
    ctx: &Arc<Ctx>,
    v: &Verified,
    owner_uid: u32,
    src: &Arc<dyn BoxSource>,
    proof: &TouchProof,
) -> Result<Proven, Refused> {
    let action = v.frame.action.as_str();
    let args = &v.frame.args;
    // 1. A decimal request id.
    let rid = Some(proof.request_id.as_str())
        .filter(|s| !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| {
            Refused::new(
                ErrorCode::BadRequest,
                "invalid",
                "request_id is a decimal number",
            )
        })?;
    // 2. The assertion, with an origin from the configured list.
    let (asr, _origin) = web_assertion(proof, &origins(ctx)).map_err(touch_refused)?;
    // 3. The credential: held by the frame's verified, ACTIVE device and by
    // the owner's touch store (R-T3b).
    let device = ctx
        .workspace
        .device(&v.device_id)
        .filter(|d| d.state == DeviceState::Active && d.owner_user == v.owner_user)
        .ok_or_else(|| mismatch("this device is not paired"))?;
    let cid = saiife_wire::b64::enc(asr.credential_id());
    if !device.touch_credentials.contains(&cid) {
        return Err(touch_refused(TouchError::Mismatch));
    }
    let c = Arc::clone(ctx);
    let want = asr.credential_id().to_vec();
    let cred = tokio::task::spawn_blocking(move || {
        c.touch
            .credentials_of(owner_uid)
            .into_iter()
            .find(|k| k.id == want)
    })
    .await
    .map_err(internal)?
    .ok_or_else(|| touch_refused(TouchError::Mismatch))?;
    let rp_id = cred.rp_id;
    let now = ctx.workspace.now();
    let tk = |e| touch_refused(e);
    match action {
        a::BOX_STEER | a::BOX_REVISE | a::BOX_RESUME | a::BOX_SPAWN => {
            let key = IssueKey::Web {
                device: v.device_id.clone(),
                request_id: rid,
            };
            let c = Arc::clone(ctx);
            let (ev, record) = tokio::task::spawn_blocking(move || {
                let iid = c.touch.instance_id();
                c.touch.consume(
                    &key,
                    owner_uid,
                    |e| ActionRecord {
                        instance_id: iid,
                        request_id: rid,
                        class: e.class,
                        summary: e.summary.clone(),
                        fields: e.fields.clone(),
                        nonce: e.nonce,
                        expires_at: e.expires_at,
                    },
                    &asr,
                    &rp_id,
                    now,
                )
            })
            .await
            .map_err(internal)?
            .map_err(tk)?;
            let (class, summary, fields) = bind(
                ctx,
                owner_uid,
                &v.owner_user,
                src,
                action,
                &bound_args(action, args),
            )
            .await?;
            if record.fields != fields || record.class != class || record.summary != summary {
                return Err(mismatch(
                    "the touch was for a different action than this frame's",
                ));
            }
            Ok(Proven::Web(ev, record))
        }
        a::BOX_LAND => {
            only(args, &["id", "diff_sha256"]).map_err(refused)?;
            let id = id_arg(args).map_err(refused)?;
            let diff = str_arg(args, "diff_sha256").map_err(refused)?.to_string();
            let s = Arc::clone(src);
            let want = id.clone();
            let (seen, pa) = tokio::task::spawn_blocking(move || {
                let seen = s.list().iter().any(|b| b.id == want);
                let pa = s
                    .pending_actions()
                    .into_iter()
                    .find(|p| p.request_id == rid);
                (seen, pa)
            })
            .await
            .map_err(internal)?;
            // A box the owner's source does not see (another user's) is
            // `not_found`, as for every other box action of the frame. The
            // `pa.box_id` check below still matters: a request id of another
            // of the owner's own boxes is `touch_mismatch`.
            if !seen {
                return Err(refused(not_found("box")));
            }
            let pa = pa.ok_or_else(|| {
                Refused::new(
                    ErrorCode::Forbidden,
                    "touch_failed",
                    "no pending action: it expired or was decided",
                )
            })?;
            // Only a land's pending action: a push (or any other kind a box
            // source may hold) is touched through its own action.
            if !is_land(&pa) {
                return Err(mismatch("the pending action is not a land"));
            }
            if pa.record.fields.get("diff_sha256") != Some(&diff) || pa.box_id.as_ref() != Some(&id)
            {
                return Err(mismatch(
                    "the touch was for another box or another diff than this frame's",
                ));
            }
            // Verified before the challenge is spent, so a proof that does
            // not verify cannot burn the daemon's own pending challenge; a
            // second valid assertion for it stops at `spend`.
            let c = Arc::clone(ctx);
            let rec = pa.record.clone();
            let ev = tokio::task::spawn_blocking(move || {
                c.touch.verify_counted(owner_uid, &rec, &asr, &rp_id, now)
            })
            .await
            .map_err(internal)?
            .map_err(tk)?;
            if !ctx
                .web_touch
                .spend(&challenge(&pa.record), pa.record.expires_at, now)
            {
                return Err(Refused::new(
                    ErrorCode::Forbidden,
                    "touch_failed",
                    "the touch was used before",
                ));
            }
            Ok(Proven::Pending(ev, pa))
        }
        a::APPROVAL_APPROVE => {
            only(args, &["id", "note"]).map_err(refused)?;
            let id = args.get("id").and_then(Value::as_u64).ok_or_else(|| {
                Refused::new(ErrorCode::BadRequest, "invalid", "id is a request number")
            })?;
            let r = pending_request(ctx, owner_uid, &v.owner_user, id)
                .await
                .map_err(refused)?;
            let class = crate::approval_ops::effective_class(ctx, &r).ok_or_else(|| {
                Refused::new(
                    ErrorCode::BadRequest,
                    "invalid",
                    format!("request #{id} needs no touch"),
                )
            })?;
            let key = IssueKey::Web {
                device: v.device_id.clone(),
                request_id: rid,
            };
            let c = Arc::clone(ctx);
            let (ev, record) = tokio::task::spawn_blocking(move || {
                let iid = c.touch.instance_id();
                c.touch.consume(
                    &key,
                    owner_uid,
                    |e| crate::approvals::action_record(&r, class, iid, e.nonce, e.expires_at),
                    &asr,
                    &rp_id,
                    now,
                )
            })
            .await
            .map_err(internal)?
            .map_err(tk)?;
            if record.request_id != id {
                return Err(mismatch("the touch was for another request"));
            }
            Ok(Proven::Approval(ev, id))
        }
        other => Err(Refused::new(
            ErrorCode::BadRequest,
            "invalid",
            format!("{other} takes no touch"),
        )),
    }
}

/// Tells the owner that a box waits in the Workspace inbox: the box id and
/// the short code to match, nothing else. No URL and no request id (§9.6):
/// nothing in a notification approves anything. Called by whoever creates
/// pending actions (plan 39's `Lands::refresh`).
pub fn notify_pending(ctx: &Ctx, pa: &PendingAction) {
    let code = pa.view().short_code;
    ctx.notifier.send(crate::notifier::NotifyEvent {
        event: saiife_policy::Event::BoxWaiting,
        id: None,
        service: None,
        operation: None,
        uid: None,
        host: crate::signals::hostname(),
        summary: format!("A box is waiting for your approval in the Workspace inbox (code {code})"),
        reason: None,
        box_id: pa.box_id.as_ref().map(|b| b.as_str().to_string()),
    });
}

/// Whether `pa` is a land (its class and its record's class both).
fn is_land(pa: &PendingAction) -> bool {
    pa.class == TouchClass::Land && pa.record.class == TouchClass::Land
}

/// `[workspace] origins` of the loaded policy, else the default.
pub fn origins(ctx: &Ctx) -> Vec<String> {
    ctx.policy()
        .system
        .map(|s| s.workspace.origins.clone())
        .unwrap_or_else(saiife_policy::system::default_origins)
}

/// The RP id of a configured origin: its host (`localhost` for
/// `http://localhost:<port>`). None for anything that is not a plain
/// `http://localhost:<port>` or `https://<host>[:port]` origin. Call it on
/// an origin from the config list, never on one the browser sent.
pub fn rp_id_of(origin: &str) -> Option<String> {
    let rest = origin
        .strip_prefix("http://localhost:")
        .map(|p| ("localhost", Some(p)))
        .or_else(|| {
            let r = origin.strip_prefix("https://")?;
            Some(match r.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (r, None),
            })
        })?;
    let (host, port) = rest;
    let host_ok = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.');
    let port_ok = port.is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    (host_ok && port_ok).then(|| host.to_string())
}

/// Builds the WebAuthn assertion of a touch frame. The origin comes from the
/// `clientDataJSON` and must be in `origins` (else `Mismatch`); everything
/// else (type, challenge, crossOrigin, RP id hash, UV, counter) is
/// `saiife_touch::verify`'s.
pub fn web_assertion(
    p: &TouchProof,
    origins: &[String],
) -> Result<(Assertion, String), TouchError> {
    let dec = |s: &str| saiife_wire::b64::dec(s).map_err(|_| TouchError::Malformed);
    let credential_id = dec(&p.credential_id)?;
    let auth_data = dec(&p.authenticator_data)?;
    let client_data_json = dec(&p.client_data_json)?;
    let signature = dec(&p.signature)?;
    let v: serde_json::Value =
        serde_json::from_slice(&client_data_json).map_err(|_| TouchError::Malformed)?;
    let origin = v
        .as_object()
        .and_then(|o| o.get("origin"))
        .and_then(|o| o.as_str())
        .ok_or(TouchError::Malformed)?
        .to_string();
    if !origins.contains(&origin) {
        return Err(TouchError::Mismatch);
    }
    Ok((
        Assertion::WebAuthn {
            credential_id,
            auth_data,
            signature,
            client_data_json,
            origin: origin.clone(),
        },
        origin,
    ))
}

/// The credential of a passkey made during pairing, after every check: the
/// device key signed the attestation (the browser, not the hub or a swapped
/// passkey, made it), `clientDataJSON` is a `webauthn.create` for exactly this
/// pairing's challenge from a configured origin, the authenticator data has
/// AT, UP, UV and the configured RP id's hash, and its credential id is the
/// claimed one. The RP id is derived from the configured origin, never taken
/// from the browser. Nothing is stored here.
pub fn passkey_credential(
    p: &PasskeyAttestation,
    pair_id: &str,
    device_pub: &[u8; 65],
    origins: &[String],
    owner_uid: u32,
    label: &str,
    now_ts: &str,
) -> Result<Credential, String> {
    let bad = |m: &str| m.to_string();
    let msg = passkey_sig_msg(pair_id, p).map_err(|_| bad("the passkey is not base64url"))?;
    let sig = saiife_wire::b64::dec_n::<64>(&p.device_sig)
        .map_err(|_| bad("the passkey is not signed by this browser's key"))?;
    if !verify_p256_domain(device_pub, PASSKEY_DOMAIN, &msg, &sig) {
        return Err(bad("the passkey is not signed by this browser's key"));
    }
    let dec = |s: &str| saiife_wire::b64::dec(s).map_err(|_| bad("the passkey is not base64url"));
    let claimed_id = dec(&p.credential_id)?;
    let auth_data = dec(&p.authenticator_data)?;
    let cdj = dec(&p.client_data_json)?;
    let v: serde_json::Value = serde_json::from_slice(&cdj)
        .map_err(|_| bad("the passkey's clientDataJSON is not JSON"))?;
    let o = v
        .as_object()
        .ok_or_else(|| bad("the passkey's clientDataJSON is not an object"))?;
    if o.get("type").and_then(|t| t.as_str()) != Some("webauthn.create") {
        return Err(bad("the passkey's clientDataJSON is not a webauthn.create"));
    }
    let want = saiife_wire::b64::enc(&passkey_challenge(pair_id, device_pub));
    if o.get("challenge").and_then(|c| c.as_str()) != Some(want.as_str()) {
        return Err(bad("the passkey was made for another pairing"));
    }
    let origin = o
        .get("origin")
        .and_then(|x| x.as_str())
        .filter(|x| origins.iter().any(|c| c == x))
        .ok_or_else(|| bad("the passkey was made for an origin this machine does not list"))?;
    if o.get("crossOrigin").and_then(|c| c.as_bool()) == Some(true) {
        return Err(bad("the passkey was made in a cross-origin frame"));
    }
    let rp_id = rp_id_of(origin).ok_or_else(|| bad("the origin has no usable RP id"))?;
    let mut c = saiife_touch::credential_from_attestation(
        &auth_data, &rp_id, label, owner_uid, None, now_ts,
    )
    .map_err(|_| bad("the passkey's authenticator data is not usable"))?;
    let ad = saiife_touch::authdata::parse(&auth_data)
        .map_err(|_| bad("the passkey's authenticator data is not usable"))?;
    if ad.flags & saiife_touch::authdata::UV == 0 {
        return Err(bad("the passkey was made without user verification"));
    }
    if c.id != claimed_id {
        return Err(bad("the passkey's credential id is not the claimed one"));
    }
    c.kind = "webauthn".into();
    c.origins = vec![origin.to_string()];
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use saiife_wire::b64;

    fn proof(cdj: &[u8]) -> TouchProof {
        TouchProof {
            request_id: "7".into(),
            credential_id: b64::enc(b"cred"),
            authenticator_data: b64::enc(b"auth"),
            client_data_json: b64::enc(cdj),
            signature: b64::enc(b"sig"),
        }
    }

    #[test]
    fn only_a_land_is_a_land() {
        let pending = |class, record_class| PendingAction {
            request_id: 1,
            class,
            box_id: None,
            summary: "x".into(),
            record: ActionRecord {
                instance_id: [0; 16],
                request_id: 1,
                class: record_class,
                summary: "x".into(),
                fields: BTreeMap::new(),
                nonce: [0; 32],
                expires_at: 1,
            },
            created_at: 0,
            expires_at: 1,
        };
        assert!(is_land(&pending(TouchClass::Land, TouchClass::Land)));
        // A push (or anything else) is not approved by a box.land frame.
        assert!(!is_land(&pending(
            TouchClass::PushProtected,
            TouchClass::PushProtected
        )));
        assert!(!is_land(&pending(TouchClass::Land, TouchClass::Deploy)));
        assert!(!is_land(&pending(TouchClass::Deploy, TouchClass::Land)));
    }

    #[test]
    fn web_touches_ids_spend_and_windows() {
        let w = WebTouches::new();
        assert_eq!((w.next_id(), w.next_id()), (1, 2));
        let c = [7u8; 32];
        assert!(w.spend(&c, 100, 50));
        assert!(!w.spend(&c, 100, 60));
        assert!(w.spend(&[8u8; 32], 100, 60));
        // An expired entry is pruned, so the challenge can be recorded again.
        assert!(w.spend(&c, 300, 101));
        let a = BoxId::parse("b-run").unwrap();
        let b = BoxId::parse("b-done").unwrap();
        assert!(!w.window_open("d1", &a, 1000));
        w.open_window("d1", &a, 1000);
        assert!(w.window_open("d1", &a, 1000));
        assert!(w.window_open("d1", &a, 1000 + STEER_WINDOW_SECS - 1));
        assert!(!w.window_open("d1", &a, 1000 + STEER_WINDOW_SECS));
        assert!(!w.window_open("d1", &b, 1000));
        assert!(!w.window_open("d2", &a, 1000));
        w.open_window("d1", &a, 1000);
        w.open_window("d1", &b, 1000);
        w.open_window("d2", &a, 1000);
        w.close_device("d1");
        assert!(!w.window_open("d1", &a, 1001) && !w.window_open("d1", &b, 1001));
        assert!(w.window_open("d2", &a, 1001));
    }

    #[test]
    fn notification_has_no_approve_link() {
        let dir = tempfile::tempdir().unwrap();
        let (ctx, _join) = crate::ops::test_ctx(dir.path(), crate::ops::Mode::Locked, 7);
        let request_id = 424_242_424_242u64;
        let pa = PendingAction {
            request_id,
            class: TouchClass::Land,
            box_id: Some(BoxId::parse("b-run").unwrap()),
            summary: "land b-run".into(),
            record: ActionRecord {
                instance_id: [0; 16],
                request_id,
                class: TouchClass::Land,
                summary: "land b-run".into(),
                fields: BTreeMap::new(),
                nonce: [3; 32],
                expires_at: 99,
            },
            created_at: 0,
            expires_at: 99,
        };
        let code = pa.view().short_code;
        notify_pending(&ctx, &pa);
        let q = ctx.notifier.queued_events();
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].event, saiife_policy::Event::BoxWaiting);
        assert_eq!(q[0].box_id.as_deref(), Some("b-run"));
        let text = q[0].payload().to_string();
        assert!(text.contains(&code), "{text}");
        assert!(text.contains("Workspace inbox"), "{text}");
        assert!(!text.contains("http"), "{text}");
        assert!(!text.contains("request_id"), "{text}");
        assert!(!text.contains(&request_id.to_string()), "{text}");
        assert!(q[0].id.is_none());
    }

    #[test]
    fn hostile_looking_input_cannot_make_a_link() {
        // What can vary is the box id and the request id. A box id that
        // looks like a URL is not a box id at all.
        for bad in [
            "http://evil.test/x",
            "b-1/../x",
            "b:1",
            "B-1",
            "b 1",
            "b-1?a=1",
        ] {
            assert!(BoxId::parse(bad).is_err(), "{bad}");
        }
        let dir = tempfile::tempdir().unwrap();
        let (ctx, _join) = crate::ops::test_ctx(dir.path(), crate::ops::Mode::Locked, 7);
        let request_id = 5_551_234_567u64;
        let pa = PendingAction {
            request_id,
            class: TouchClass::Land,
            box_id: Some(BoxId::parse("http-evil-test").unwrap()),
            summary: "see https://evil.test/approve?id=5551234567".into(),
            record: ActionRecord {
                instance_id: [0; 16],
                request_id,
                class: TouchClass::Land,
                summary: "see https://evil.test/approve?id=5551234567".into(),
                fields: BTreeMap::new(),
                nonce: [9; 32],
                expires_at: 99,
            },
            created_at: 0,
            expires_at: 99,
        };
        notify_pending(&ctx, &pa);
        let ev = ctx.notifier.queued_events().remove(0);
        let text = ev.payload().to_string();
        // Neither the pending action's own summary nor its request id leaks.
        for needle in ["://", "evil.test", "approve?", "request_id", "5551234567"] {
            assert!(!text.contains(needle), "{needle} in {text}");
        }
        assert_eq!(ev.box_id.as_deref(), Some("http-evil-test"));
        assert!(ev.id.is_none());
    }

    fn list() -> Vec<String> {
        vec![
            "http://localhost:47810".to_string(),
            "https://app.saiife.com".to_string(),
        ]
    }

    #[test]
    fn rp_id_of_cases() {
        assert_eq!(
            rp_id_of("http://localhost:47810").as_deref(),
            Some("localhost")
        );
        assert_eq!(
            rp_id_of("https://app.saiife.com:8443").as_deref(),
            Some("app.saiife.com")
        );
        assert_eq!(
            rp_id_of("https://app.saiife.com").as_deref(),
            Some("app.saiife.com")
        );
        assert_eq!(rp_id_of("javascript:x"), None);
        assert_eq!(rp_id_of("http://evil.test"), None);
        assert_eq!(rp_id_of("https://"), None);
        assert_eq!(rp_id_of("https://a.test/x"), None);
    }

    #[test]
    fn web_assertion_rules() {
        let o = list();
        let mm = |p: &TouchProof| web_assertion(p, &o).unwrap_err();
        // Bad base64 in each field.
        for f in 0..4 {
            let mut p = proof(br#"{"origin":"http://localhost:47810"}"#);
            let bad = "a=b*".to_string();
            match f {
                0 => p.credential_id = bad,
                1 => p.authenticator_data = bad,
                2 => p.client_data_json = bad,
                _ => p.signature = bad,
            }
            assert_eq!(mm(&p), TouchError::Malformed, "field {f}");
        }
        // Not an object, not JSON, no origin, origin not a string.
        for cdj in [
            &b"[1]"[..],
            b"\"x\"",
            b"nope",
            b"{}",
            br#"{"origin":5}"#,
            br#"{"type":"webauthn.get"}"#,
        ] {
            assert_eq!(
                mm(&proof(cdj)),
                TouchError::Malformed,
                "{}",
                String::from_utf8_lossy(cdj)
            );
        }
        // Outside the list.
        for origin in [
            "http://evil.test",
            "http://localhost:47811",
            "https://localhost:47810",
            "https://app.saiife.com/",
            "https://APP.saiife.com",
            "",
        ] {
            let cdj = format!(r#"{{"origin":"{origin}"}}"#);
            assert_eq!(mm(&proof(cdj.as_bytes())), TouchError::Mismatch, "{origin}");
        }
        // An empty list refuses everything.
        let p = proof(br#"{"origin":"http://localhost:47810"}"#);
        assert_eq!(web_assertion(&p, &[]).unwrap_err(), TouchError::Mismatch);
        // A good one keeps every byte.
        let cdj = br#"{"type":"webauthn.get","challenge":"x","origin":"https://app.saiife.com","crossOrigin":false}"#;
        let (a, origin) = web_assertion(&proof(cdj), &o).unwrap();
        assert_eq!(origin, "https://app.saiife.com");
        match a {
            Assertion::WebAuthn {
                credential_id,
                auth_data,
                signature,
                client_data_json,
                origin,
            } => {
                assert_eq!(credential_id, b"cred");
                assert_eq!(auth_data, b"auth");
                assert_eq!(signature, b"sig");
                assert_eq!(client_data_json, cdj);
                assert_eq!(origin, "https://app.saiife.com");
            }
            other => panic!("not a web assertion: {other:?}"),
        }
    }
}
