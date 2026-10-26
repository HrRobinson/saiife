//! `secret.add|rotate|remove|list` (spec §8.7): the admin's way into the
//! vault. Every op is for root and `[admin] groups` only; anyone else gets
//! `forbidden` and a `secret` record with `decision = "deny"`. A record or an
//! answer never holds a field value, and an error never echoes `fields`.

use crate::ops::{now_ts, Ctx};
use crate::vault::{valid_name, Entry, Kind, Vault, VaultState};
use saiife_audit::DecisionKind;
use saiife_ipc::msg::{
    err, ok, ErrorCode, Request, OP_SECRET_ADD, OP_SECRET_LIST, OP_SECRET_REMOVE, OP_SECRET_ROTATE,
};
use saiife_ipc::peer::{comm, PeerCred};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Shorter values are never stored: the masking pass skips them.
const MIN_VALUE_BYTES: usize = 4;
const MAX_SERVICES: usize = 64;
const MAX_FIELD_BYTES: usize = 64 * 1024;

type Refusal = (ErrorCode, String);

fn bad(m: impl Into<String>) -> Refusal {
    (ErrorCode::BadRequest, m.into())
}

/// The record's `event` for an op.
fn event_of(op: &str) -> &'static str {
    match op {
        OP_SECRET_ADD => "secret_add",
        OP_SECRET_ROTATE => "secret_rotate",
        OP_SECRET_REMOVE => "secret_remove",
        _ => "secret_list",
    }
}

pub async fn handle(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    let id = req.id;
    let event = event_of(&req.op);
    // Only a well-formed name goes into a record.
    let name = req
        .args
        .get("name")
        .and_then(Value::as_str)
        .filter(|n| valid_name(n))
        .unwrap_or("")
        .to_string();
    if !ctx.is_admin(peer.uid).await {
        let mut r = record(ctx, peer, event, &name).await;
        r.decision = DecisionKind::Deny;
        r.reason = Some("secret ops are for root and [admin] groups".into());
        if let Err(e) = ctx.writer.append(r).await {
            eprintln!("saiifed: warning: cannot write {event} record: {e}");
        }
        return err(
            id,
            ErrorCode::Forbidden,
            "secret ops are for root and [admin] groups",
        );
    }
    let uid = peer.uid;
    let c = Arc::clone(ctx);
    // The vault write fsyncs: keep it off the runtime thread.
    let done = tokio::task::spawn_blocking(move || execute(&c, uid, req)).await;
    match done {
        Ok(Ok(fields)) => {
            if event != "secret_list" {
                let r = record(ctx, peer, event, &name).await;
                if let Err(e) = ctx.writer.append(r).await {
                    // The change is made; say so rather than hide it.
                    return err(
                        id,
                        ErrorCode::Internal,
                        &format!("the change was made but its audit record failed: {e}"),
                    );
                }
            }
            ok(id, fields)
        }
        Ok(Err((code, m))) => err(id, code, &m),
        Err(_) => err(id, ErrorCode::Internal, "secret op failed"),
    }
}

async fn record(ctx: &Ctx, peer: &PeerCred, event: &str, name: &str) -> saiife_audit::Record {
    let mut r = ctx.record("secret", &format!("{event} {name}"));
    r.uid = Some(peer.uid);
    r.user = ctx.name_of(peer.uid).await;
    r.extra.insert("event".into(), event.into());
    r.extra.insert("name".into(), name.into());
    r.extra.insert(
        "peer".into(),
        json!({"pid": peer.pid, "comm": comm(peer.pid)}),
    );
    r
}

fn execute(ctx: &Ctx, uid: u32, req: Request) -> Result<Map<String, Value>, Refusal> {
    // Parse before touching the vault, so a bad request is a bad request
    // whatever state the vault is in.
    let parsed = parse(&req)?;
    let mut guard = ctx.vault.lock().unwrap_or_else(|p| p.into_inner());
    let vault = match &mut *guard {
        VaultState::Ready(v) => v,
        VaultState::Unavailable(_) => {
            return Err((
                ErrorCode::VaultUnavailable,
                format!(
                    "vault cannot be read; restore it or remove {} by hand",
                    ctx.vault_path.display()
                ),
            ))
        }
    };
    run(vault, uid, parsed)
}

enum Parsed {
    Add {
        name: String,
        kind: Kind,
        fields: BTreeMap<String, Zeroizing<String>>,
        services: Vec<String>,
    },
    Rotate {
        name: String,
        fields: BTreeMap<String, Zeroizing<String>>,
    },
    Remove {
        name: String,
    },
    List,
}

fn parse(req: &Request) -> Result<Parsed, Refusal> {
    if req.op == OP_SECRET_LIST {
        return Ok(Parsed::List);
    }
    let name = match req.args.get("name").and_then(Value::as_str) {
        Some(n) if valid_name(n) => n.to_string(),
        Some(_) => return Err(bad("invalid secret name")),
        None => return Err(bad(format!("{} takes a name", req.op))),
    };
    match req.op.as_str() {
        OP_SECRET_REMOVE => Ok(Parsed::Remove { name }),
        OP_SECRET_ADD => {
            let kind = parse_kind(req.args.get("kind"))?;
            let services = parse_services(req.args.get("allowed_services"))?;
            let fields = parse_fields(req.args.get("fields"), kind)?;
            Ok(Parsed::Add {
                name,
                kind,
                fields,
                services,
            })
        }
        OP_SECRET_ROTATE => {
            // The kind is the stored one; its field names are checked
            // against it in `run`.
            let fields = parse_fields_any(req.args.get("fields"))?;
            Ok(Parsed::Rotate { name, fields })
        }
        other => Err(bad(format!("unknown op {other:?}"))),
    }
}

fn parse_kind(v: Option<&Value>) -> Result<Kind, Refusal> {
    let Some(k) = v.and_then(Value::as_str) else {
        return Err(bad("secret.add takes a kind"));
    };
    match k {
        "token" => Ok(Kind::Token),
        "basic" => Ok(Kind::Basic),
        "header" => Ok(Kind::Header),
        "oauth2" | "aws" | "gcp_sa" | "azure_sp" => {
            Err(bad(format!("kind {k} comes with plans 14–15")))
        }
        _ => Err(bad("unknown kind (token, basic or header)")),
    }
}

fn parse_services(v: Option<&Value>) -> Result<Vec<String>, Refusal> {
    let Some(a) = v.and_then(Value::as_array) else {
        return Err(bad("secret.add takes allowed_services"));
    };
    if a.is_empty() {
        return Err(bad("a secret needs at least one allowed service"));
    }
    if a.len() > MAX_SERVICES {
        return Err(bad("too many allowed services"));
    }
    let mut out: Vec<String> = Vec::new();
    for s in a {
        match s.as_str() {
            Some(s) if valid_name(s) => {
                if !out.iter().any(|o| o == s) {
                    out.push(s.to_string());
                }
            }
            _ => return Err(bad("invalid service name in allowed_services")),
        }
    }
    Ok(out)
}

/// The field names a kind takes.
fn field_names(kind: Kind) -> &'static [&'static str] {
    match kind {
        Kind::Token => &["token"],
        Kind::Basic => &["username", "password"],
        Kind::Header => &["value"],
    }
}

/// Fields whose value may be as short as one byte: a user name is not a
/// secret.
fn short_ok(name: &str) -> bool {
    name == "username"
}

fn parse_fields_any(v: Option<&Value>) -> Result<BTreeMap<String, Zeroizing<String>>, Refusal> {
    // Never echo what was sent: no serde error text, no value.
    let Some(o) = v.and_then(Value::as_object) else {
        return Err(bad("fields must be an object of strings"));
    };
    let mut out = BTreeMap::new();
    for (k, v) in o {
        let Some(s) = v.as_str() else {
            return Err(bad("fields must be an object of strings"));
        };
        if s.len() > MAX_FIELD_BYTES {
            return Err(bad("secret value is too long"));
        }
        out.insert(k.clone(), Zeroizing::new(s.to_string()));
    }
    Ok(out)
}

/// Exactly the kind's fields, each long enough.
fn check_fields(kind: Kind, fields: &BTreeMap<String, Zeroizing<String>>) -> Result<(), Refusal> {
    let want = field_names(kind);
    if fields.len() != want.len() || !want.iter().all(|w| fields.contains_key(*w)) {
        return Err(bad(format!(
            "this kind takes the fields {}",
            want.join(", ")
        )));
    }
    for (k, v) in fields {
        let min = if short_ok(k) { 1 } else { MIN_VALUE_BYTES };
        if v.len() < min {
            return Err(bad("secret value is too short"));
        }
    }
    Ok(())
}

fn parse_fields(
    v: Option<&Value>,
    kind: Kind,
) -> Result<BTreeMap<String, Zeroizing<String>>, Refusal> {
    let f = parse_fields_any(v)?;
    check_fields(kind, &f)?;
    Ok(f)
}

fn run(vault: &mut Vault, uid: u32, p: Parsed) -> Result<Map<String, Value>, Refusal> {
    let io = |_e: std::io::Error| (ErrorCode::Internal, "cannot write the vault".to_string());
    match p {
        Parsed::List => {
            let secrets: Vec<Value> = vault
                .list()
                .into_iter()
                .map(|m| {
                    json!({
                        "name": m.name,
                        "kind": m.kind,
                        "allowed_services": m.allowed_services,
                        "created_by": m.created_by,
                        "created": m.created,
                        "last_used": m.last_used,
                        "rotate_after": m.rotate_after,
                    })
                })
                .collect();
            let mut m = Map::new();
            m.insert("secrets".into(), Value::Array(secrets));
            Ok(m)
        }
        Parsed::Add {
            name,
            kind,
            fields,
            services,
        } => {
            if vault.get(&name).is_some() {
                return Err(bad(format!(
                    "secret {name} exists; use rotate to replace its value"
                )));
            }
            vault
                .put(Entry {
                    name,
                    kind,
                    fields,
                    allowed_services: services,
                    created_by: uid,
                    created: now_ts(),
                    last_used: None,
                    rotate_after: None,
                })
                .map_err(io)?;
            Ok(Map::new())
        }
        Parsed::Rotate { name, fields } => {
            let Some(old) = vault.get(&name) else {
                return Err(bad(format!("no secret named {name}")));
            };
            check_fields(old.kind, &fields)?;
            let mut e = old.clone();
            e.fields = fields;
            vault.put(e).map_err(io)?;
            Ok(Map::new())
        }
        Parsed::Remove { name } => {
            if !vault.remove(&name).map_err(io)? {
                return Err(bad(format!("no secret named {name}")));
            }
            Ok(Map::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(op: &str, args: Value) -> Request {
        Request {
            id: 1,
            op: op.into(),
            args: args.as_object().unwrap().clone(),
        }
    }

    fn msg(r: Result<Parsed, Refusal>) -> String {
        match r {
            Ok(_) => "ok".into(),
            Err((_, m)) => m,
        }
    }

    #[test]
    fn add_checks_kind_fields_and_services() {
        let good =
            json!({"name":"a1","kind":"token","fields":{"token":"abcd"},"allowed_services":["s"]});
        assert_eq!(msg(parse(&req(OP_SECRET_ADD, good))), "ok");
        let short =
            json!({"name":"a1","kind":"token","fields":{"token":"abc"},"allowed_services":["s"]});
        assert_eq!(
            msg(parse(&req(OP_SECRET_ADD, short))),
            "secret value is too short"
        );
        let wrong = json!({"name":"a1","kind":"token","fields":{"value":"abcdef"},"allowed_services":["s"]});
        let m = msg(parse(&req(OP_SECRET_ADD, wrong)));
        assert!(m.contains("token") && !m.contains("abcdef"), "{m}");
        let none =
            json!({"name":"a1","kind":"token","fields":{"token":"abcdef"},"allowed_services":[]});
        assert!(msg(parse(&req(OP_SECRET_ADD, none))).contains("at least one"));
        let oauth = json!({"name":"a1","kind":"oauth2","fields":{},"allowed_services":["s"]});
        assert_eq!(
            msg(parse(&req(OP_SECRET_ADD, oauth))),
            "kind oauth2 comes with plans 14–15"
        );
        let nonstr = json!({"name":"a1","kind":"token","fields":{"token":12345678},"allowed_services":["s"]});
        assert_eq!(
            msg(parse(&req(OP_SECRET_ADD, nonstr))),
            "fields must be an object of strings"
        );
    }

    #[test]
    fn basic_username_may_be_short_password_may_not() {
        let ok_ = json!({"name":"a1","kind":"basic","fields":{"username":"bo","password":"abcd"},"allowed_services":["s"]});
        assert_eq!(msg(parse(&req(OP_SECRET_ADD, ok_))), "ok");
        let short = json!({"name":"a1","kind":"basic","fields":{"username":"bob","password":"abc"},"allowed_services":["s"]});
        assert_eq!(
            msg(parse(&req(OP_SECRET_ADD, short))),
            "secret value is too short"
        );
    }

    #[test]
    fn bad_names_are_refused() {
        let r = json!({"name":"Bad Name","kind":"token","fields":{"token":"abcd"},"allowed_services":["s"]});
        assert_eq!(msg(parse(&req(OP_SECRET_ADD, r))), "invalid secret name");
        assert_eq!(
            msg(parse(&req(OP_SECRET_REMOVE, json!({"name":"../x"})))),
            "invalid secret name"
        );
    }
}
