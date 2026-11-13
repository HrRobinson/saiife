//! Workspace touches (plan 31): the origin list and the web assertion.
//!
//! The browser and the hub are untrusted: the origin an assertion was made
//! for is read from its own `clientDataJSON` (which `verify` binds to the
//! signature) and must be one the machine's config lists. The RP id is
//! derived from the configured origin, never from the browser.

use crate::ops::Ctx;
use crate::workspace_link::{
    blocking, id_arg, invalid, only, str_arg, text_arg, uid_of, Fail, Refused,
};
use saiife_ipc::msg::ErrorCode;
use saiife_touch::{
    challenge, short_code, ActionRecord, Assertion, Credential, TouchClass, TouchError,
    TouchRequest,
};
use saiife_wire::frame::TouchProof;
use saiife_wire::level::{actions as a, spawn_level, Level};
use saiife_wire::pair::{passkey_challenge, passkey_sig_msg, PasskeyAttestation, PASSKEY_DOMAIN};
use saiife_wire::sig::verify_p256_domain;
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
    src: &Arc<dyn BoxSource>,
    action: &str,
    args: &Map<String, Value>,
) -> Result<(TouchClass, String, BTreeMap<String, String>), Refused> {
    bind_inner(ctx, owner_uid, src, action, args)
        .await
        .map_err(refused)
}

async fn bind_inner(
    ctx: &Arc<Ctx>,
    owner_uid: u32,
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
            let r = pending_request(ctx, owner_uid, rid).await?;
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

/// Pending approval request `rid`, when the device owner may decide it.
async fn pending_request(
    ctx: &Arc<Ctx>,
    owner_uid: u32,
    rid: u64,
) -> Result<crate::approvals::Request, Fail> {
    use crate::approval_ops as ops;
    let peer = saiife_ipc::peer::PeerCred {
        uid: owner_uid,
        gid: owner_uid,
        pid: 0,
        sid: None,
        group_sids: Vec::new(),
    };
    let r = match ops::visible(ctx, &peer, rid).await {
        Err(()) => {
            return Err(Fail::Policy(Refused::new(
                ErrorCode::Unavailable,
                "unavailable",
                "approvals are not available on this machine",
            )))
        }
        Ok(None) => return Err(not_found("approval request")),
        Ok(Some(r)) => r,
    };
    if r.state != crate::approvals::State::Pending {
        return Err(invalid(format!("request #{rid} is not pending")));
    }
    if !ops::is_approver(ctx, &peer).await {
        return Err(Fail::Policy(Refused::new(
            ErrorCode::Forbidden,
            "not_approver",
            format!("only an approver can touch for request #{rid}"),
        )));
    }
    Ok(r)
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
    let (class, summary, fields) = bind(ctx, owner_uid, &src, &action, &inner).await?;
    // The device's passkeys that the touch store still holds, for one RP id.
    let held = device.touch_credentials;
    let c = Arc::clone(ctx);
    let creds: Vec<Credential> =
        tokio::task::spawn_blocking(move || c.touch.credentials_of(owner_uid))
            .await
            .map_err(|e| Refused::new(ErrorCode::Internal, "internal", e.to_string()))?
            .into_iter()
            .filter(|c| c.kind == "webauthn" && held.contains(&saiife_wire::b64::enc(&c.id)))
            .collect();
    let Some(rp_id) = creds.first().map(|c| c.rp_id.clone()) else {
        return Err(Refused::new(
            ErrorCode::Unavailable,
            "touch_unavailable",
            "this browser has no passkey: pair it again to add one",
        ));
    };
    let allow: Vec<Vec<u8>> = creds
        .into_iter()
        .filter(|c| c.rp_id == rp_id)
        .map(|c| c.id)
        .collect();
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
