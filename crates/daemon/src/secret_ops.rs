//! `secret.add|rotate|remove|list` (spec §8.7): the admin's way into the
//! vault. Every op is for root and `[admin] groups` only; anyone else gets
//! `forbidden` and a `secret` record with `decision = "deny"`. A record or an
//! answer never holds a field value, and an error never echoes `fields`.
//!
//! `secret.add` from `saiife secret import` also carries `backup {path,
//! bytes_b64}`: the original bytes of the file the credential came from.
//! They are written to the import-backup dir before the vault, and the add
//! fails (with nothing stored) when that write fails. The bytes are a
//! secret too and are never echoed.

use crate::ops::{now_ts, Ctx, Notice};
use crate::vault::{valid_name, Entry, Kind, Vault, VaultState};
use saiife_audit::DecisionKind;
use saiife_ipc::msg::{
    err, ok, ErrorCode, Request, OP_SECRET_ADD, OP_SECRET_LIST, OP_SECRET_REMOVE, OP_SECRET_ROTATE,
};
use saiife_ipc::peer::{comm, PeerCred};
use saiife_policy::{is_interpreter, scope_for};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::Zeroizing;

/// Shorter values are never stored: the masking pass skips them.
const MIN_VALUE_BYTES: usize = 4;
const MAX_SERVICES: usize = 64;
const MAX_FIELD_BYTES: usize = 64 * 1024;

type Refusal = (ErrorCode, String);

/// The audit-volume gate; an unknown free space counts as too little.
fn gate(
    free: std::io::Result<u64>,
    min_free_mb: u64,
    peer_uid: u32,
    own_uid: u32,
) -> Result<(), ErrorCode> {
    crate::disk::disk_gate(free.unwrap_or(0), min_free_mb, peer_uid, own_uid)
}

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
    // The source path of an import goes into the record (never its bytes).
    let source = req
        .args
        .get("backup")
        .and_then(|b| b.get("path"))
        .and_then(Value::as_str)
        .filter(|p| valid_source(p))
        .map(str::to_string);
    // Only a well-formed name goes into a record.
    let name = req
        .args
        .get("name")
        .and_then(Value::as_str)
        .filter(|n| valid_name(n))
        .unwrap_or("")
        .to_string();
    // Whatever writes a record (every op but an admin's list) is refused
    // before it changes anything when the audit volume is below the floor
    // (same gate as audit.append).
    let admin = ctx.is_admin(peer.uid).await;
    if event != "secret_list" || !admin {
        let free = crate::disk::free_mb(&ctx.audit_dir);
        if let Err(code) = gate(free, ctx.policy().min_free_mb, peer.uid, ctx.own_uid) {
            ctx.notice(peer.uid, Notice::LowDisk);
            return err(id, code, "the audit volume is below [audit] min_free_mb");
        }
    }
    if !admin {
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
                let mut r = record(ctx, peer, event, &name).await;
                if let Some(src) = &source {
                    r.extra.insert("imported_from".into(), src.clone().into());
                }
                let appended = ctx.writer.append(r).await;
                // Test seam, debug builds only: the record "fails" after the change.
                #[cfg(debug_assertions)]
                let appended = if std::env::var_os("SAIIFE_DAEMON_FAULT")
                    .is_some_and(|v| v == "secret_record")
                {
                    appended.and(Err("injected fault".to_string()))
                } else {
                    appended
                };
                if let Err(e) = appended {
                    // The change is made; say so rather than hide it.
                    eprintln!("saiife: {event} {name} committed without audit record: {e}");
                    return err(
                        id,
                        ErrorCode::Unrecorded,
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
    run(vault, uid, parsed, &ctx.backup_dir)
}

/// A backup's source path: absolute, no NUL, bounded.
fn valid_source(p: &str) -> bool {
    p.starts_with('/') && p.len() <= 4096 && !p.contains('\0')
}

/// The original bytes of an imported file and where they came from.
struct Backup {
    source: String,
    bytes: Zeroizing<Vec<u8>>,
}

fn parse_backup(v: Option<&Value>) -> Result<Option<Backup>, Refusal> {
    use base64::Engine as _;
    let Some(v) = v else {
        return Ok(None);
    };
    // Never echo what was sent.
    let (Some(path), Some(b64)) = (
        v.get("path").and_then(Value::as_str),
        v.get("bytes_b64").and_then(Value::as_str),
    ) else {
        return Err(bad("backup takes a path and bytes_b64"));
    };
    if !valid_source(path) {
        return Err(bad("the backup path must be absolute"));
    }
    if b64.len() > crate::import_backup::MAX_BACKUP_BYTES.div_ceil(3) * 4 {
        return Err(bad("the backup is too large"));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| bad("the backup is not valid base64"))?;
    let bytes = Zeroizing::new(bytes);
    if bytes.len() > crate::import_backup::MAX_BACKUP_BYTES {
        return Err(bad("the backup is too large"));
    }
    Ok(Some(Backup {
        source: path.to_string(),
        bytes,
    }))
}

enum Parsed {
    Add {
        name: String,
        kind: Kind,
        fields: BTreeMap<String, Zeroizing<String>>,
        services: Vec<String>,
        backup: Option<Backup>,
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
            let backup = parse_backup(req.args.get("backup"))?;
            Ok(Parsed::Add {
                name,
                kind,
                fields,
                services,
                backup,
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
        if s.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(bad("secret value has control characters"));
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

fn run(
    vault: &mut Vault,
    uid: u32,
    p: Parsed,
    backup_dir: &Path,
) -> Result<Map<String, Value>, Refusal> {
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
            backup,
        } => {
            if vault.get(&name).is_some() {
                return Err(bad(format!(
                    "secret {name} exists; use rotate to replace its value"
                )));
            }
            // The backup first: no backup, no add (and so no rewrite).
            let written = match &backup {
                Some(b) => Some(
                    crate::import_backup::write(
                        backup_dir,
                        crate::import_backup::now(),
                        &b.source,
                        &b.bytes,
                    )
                    .map_err(|e| {
                        eprintln!("saiifed: warning: cannot write an import backup: {e}");
                        (ErrorCode::Internal, "cannot write the backup".to_string())
                    })?,
                ),
                None => None,
            };
            let put = vault.put(Entry {
                name,
                kind,
                fields,
                allowed_services: services,
                created_by: uid,
                created: now_ts(),
                last_used: None,
                rotate_after: None,
            });
            if let Err(e) = put {
                if let Some(p) = &written {
                    let _ = std::fs::remove_file(p);
                }
                return Err(io(e));
            }
            let mut m = Map::new();
            if written.is_some() {
                m.insert("backup".into(), true.into());
            }
            Ok(m)
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

// ---- secret.lease (spec §6.14) ----

/// Longest `exe` a lease takes.
const MAX_EXE_BYTES: usize = 4096;

/// A refused lease: the rule and why.
struct Deny {
    rule: &'static str,
    detail: String,
}

fn deny(rule: &'static str, detail: impl Into<String>) -> Deny {
    Deny {
        rule,
        detail: detail.into(),
    }
}

/// `secret.lease {name, exe}`: the value of secret `name` for one command,
/// only when the caller is in a scope and `exe` is a listed, root-owned,
/// non-interpreter executable. Every answer, grant or refusal, is a
/// `secret` record (`event = "secret_use"`).
///
/// Trust boundary: any process running as the agent's uid can ask for a
/// lease of a listed secret, and the `exe` check binds only the honest
/// client (a dishonest one names a listed program and then runs something
/// else). The boundary is the uid plus its scope. Prefer a connector
/// wherever one exists.
///
/// The interpreter denylist is best effort (see `INTERPRETERS` in the
/// policy crate): `run_allow` should hold only purpose-built,
/// argument-constrained programs.
pub async fn lease(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    let id = req.id;
    let name = match req.args.get("name").and_then(Value::as_str) {
        Some(n) if valid_name(n) => n.to_string(),
        _ => return err(id, ErrorCode::BadRequest, "secret.lease takes a valid name"),
    };
    let exe = match req.args.get("exe").and_then(Value::as_str) {
        Some(e) if !e.is_empty() && e.len() <= MAX_EXE_BYTES && !e.contains('\0') => e.to_string(),
        _ => return err(id, ErrorCode::BadRequest, "secret.lease takes an exe path"),
    };
    let free = crate::disk::free_mb(&ctx.audit_dir);
    if let Err(code) = gate(free, ctx.policy().min_free_mb, peer.uid, ctx.own_uid) {
        ctx.notice(peer.uid, Notice::LowDisk);
        return err(id, code, "the audit volume is below [audit] min_free_mb");
    }
    let verdict = match check_lease(ctx, peer.uid, &name, &exe).await {
        Ok(()) => take_value(ctx, &name).await,
        Err(d) => Err(d),
    };
    let mut r = use_record(ctx, peer, &name, &exe).await;
    match verdict {
        Ok((value, kind)) => {
            if let Err(e) = ctx.writer.append(r).await {
                // No record, no value.
                return err(
                    id,
                    ErrorCode::Internal,
                    &format!("cannot write the audit record: {e}"),
                );
            }
            let mut m = Map::new();
            m.insert("value".into(), Value::String(value.to_string()));
            m.insert(
                "kind".into(),
                match kind {
                    Kind::Token => "token",
                    Kind::Basic => "basic",
                    Kind::Header => "header",
                }
                .into(),
            );
            ok(id, m)
        }
        Err(Deny { rule, detail }) => {
            r.decision = DecisionKind::Deny;
            r.rule = Some(rule.to_string());
            r.reason = Some(detail.clone());
            if let Err(e) = ctx.writer.append(r).await {
                eprintln!("saiifed: warning: cannot write secret_use record: {e}");
            }
            let code = if rule == "vault_unavailable" {
                ErrorCode::VaultUnavailable
            } else {
                ErrorCode::Denied
            };
            let mut v = err(id, code, &format!("{rule}: {detail}"));
            if let Some(o) = v.as_object_mut() {
                o.insert("rule".into(), rule.into());
            }
            v
        }
    }
}

async fn use_record(ctx: &Ctx, peer: &PeerCred, name: &str, exe: &str) -> saiife_audit::Record {
    let mut r = ctx.record("secret", &format!("run {name} {exe}"));
    r.uid = Some(peer.uid);
    r.user = ctx.name_of(peer.uid).await;
    r.extra.insert("event".into(), "secret_use".into());
    r.extra.insert("name".into(), name.into());
    r.extra.insert(
        "peer".into(),
        json!({"pid": peer.pid, "comm": comm(peer.pid)}),
    );
    r
}

/// Scope, then the executable.
async fn check_lease(ctx: &Arc<Ctx>, uid: u32, name: &str, exe: &str) -> Result<(), Deny> {
    let Some(sys) = ctx.policy().system else {
        return Err(deny("run_not_allowed", "no valid policy is loaded"));
    };
    let Some(user) = ctx.name_of(uid).await else {
        return Err(deny("no_scope", "the caller has no user name"));
    };
    let dir = Arc::clone(&ctx.directory);
    let cfg = Arc::clone(&sys);
    let scope = tokio::task::spawn_blocking(move || {
        scope_for(&cfg, dir.as_ref(), &user).map(|s| s.map(|s| s.name.clone()))
    })
    .await
    .map_err(|_| deny("run_not_allowed", "scope lookup failed"))?;
    match scope {
        Ok(Some(_)) => {}
        Ok(None) => return Err(deny("no_scope", "the caller is in no scope")),
        Err(_) => {
            return Err(deny(
                "scope_conflict",
                "the caller is in more than one scope",
            ))
        }
    }
    let allow: Vec<PathBuf> = sys
        .secrets
        .get(name)
        .map(|s| s.run_allow.clone())
        .unwrap_or_default();
    let exe = PathBuf::from(exe);
    tokio::task::spawn_blocking(move || check_exe(&exe, &allow))
        .await
        .map_err(|_| deny("run_not_allowed", "executable check failed"))?
}

/// A listed entry must be the canonical file itself: no symlink hop
/// anywhere in it, and (so) the same basename. A multi-call binary reached
/// through a link (`printenv` -> `coreutils`) therefore needs the real file
/// listed.
fn entry_is_canonical(entry: &Path, canonical: &Path) -> Result<(), &'static str> {
    if entry == canonical {
        return Ok(());
    }
    if entry.file_name() != canonical.file_name() {
        return Err("the listed name differs from the real file's name; list the real file");
    }
    Err("the listed path is not canonical (a symlink is in it); list the real file")
}

/// The executable: absolute and canonical, listed as itself, no
/// interpreter by its resolved name, a regular file, and root-owned along
/// its whole path.
fn check_exe(exe: &Path, allow: &[PathBuf]) -> Result<(), Deny> {
    let no = |d: &str| deny("run_not_allowed", d);
    if !exe.is_absolute() {
        return Err(no("the executable path is not absolute"));
    }
    // Only an exact match counts: a link in run_allow never grants its target.
    if !allow.iter().any(|a| a == exe) {
        // Say why when an entry resolves to this file by another path.
        for a in allow {
            if std::fs::canonicalize(a).is_ok_and(|c| c == exe) {
                if let Err(why) = entry_is_canonical(a, exe) {
                    return Err(no(why));
                }
            }
        }
        return Err(no("the executable is not in run_allow for this secret"));
    }
    match std::fs::canonicalize(exe) {
        Ok(c) if c == exe => {}
        _ => return Err(no("the executable path is not canonical")),
    }
    if is_interpreter(exe) {
        return Err(no("the executable is an interpreter or shell"));
    }
    match std::fs::metadata(exe) {
        Ok(m) if m.is_file() => {}
        _ => return Err(no("the executable is not a regular file")),
    }
    saiife_system::fsops::root_owned_chain(exe).map_err(|e| no(&format!("not root-owned: {e}")))
}

/// The value for the answer, and the use noted in the vault.
async fn take_value(ctx: &Arc<Ctx>, name: &str) -> Result<(Zeroizing<String>, Kind), Deny> {
    let c = Arc::clone(ctx);
    let n = name.to_string();
    tokio::task::spawn_blocking(move || {
        let mut guard = c.vault.lock().unwrap_or_else(|p| p.into_inner());
        let vault = match &mut *guard {
            VaultState::Ready(v) => v,
            VaultState::Unavailable(_) => {
                return Err(deny("vault_unavailable", "the vault cannot be read"))
            }
        };
        let Some(e) = vault.get(&n) else {
            return Err(deny("unknown_secret", "no such secret"));
        };
        let field = |k: &str| e.fields.get(k).map(|v| v.as_str()).unwrap_or("");
        let value = match e.kind {
            Kind::Token => Zeroizing::new(field("token").to_string()),
            Kind::Basic => Zeroizing::new(format!("{}:{}", field("username"), field("password"))),
            Kind::Header => Zeroizing::new(field("value").to_string()),
        };
        let kind = e.kind;
        vault.touch(&n, &now_ts());
        Ok((value, kind))
    })
    .await
    .map_err(|_| deny("run_not_allowed", "vault read failed"))?
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
    fn control_characters_are_refused_and_not_echoed() {
        for v in ["abcd\n", "ab\r\ncd", "abc\td", "abc\u{7f}d", "ab\u{0}cd"] {
            let r =
                json!({"name":"a1","kind":"token","fields":{"token":v},"allowed_services":["s"]});
            let m = msg(parse(&req(OP_SECRET_ADD, r)));
            assert_eq!(m, "secret value has control characters", "{v:?}");
        }
        // Stored exactly: a clean value parses to itself.
        let r = json!({"name":"a1","kind":"token","fields":{"token":"header-value-123"},"allowed_services":["s"]});
        match parse(&req(OP_SECRET_ADD, r)) {
            Ok(Parsed::Add { fields, .. }) => assert_eq!(&*fields["token"], "header-value-123"),
            _ => panic!("not parsed"),
        }
        let r = json!({"name":"a1","fields":{"token":"abcd\n"}});
        assert_eq!(
            msg(parse(&req(OP_SECRET_ROTATE, r))),
            "secret value has control characters"
        );
    }

    #[test]
    fn gate_refuses_below_the_floor_and_fails_closed() {
        let io_err = || Err(std::io::Error::other("x"));
        assert_eq!(gate(Ok(10), 512, 1000, 990), Err(ErrorCode::LowDisk));
        assert_eq!(gate(Ok(512), 512, 1000, 990), Ok(()));
        assert_eq!(gate(io_err(), 512, 1000, 990), Err(ErrorCode::LowDisk));
    }

    #[test]
    fn backup_is_checked_and_never_echoed() {
        let add = |backup: Value| json!({"name":"a1","kind":"token","fields":{"token":"abcd"},"allowed_services":["s"],"backup":backup});
        let good = add(json!({"path":"/h/.env","bytes_b64":"QT0xCg=="}));
        match parse(&req(OP_SECRET_ADD, good)) {
            Ok(Parsed::Add {
                backup: Some(b), ..
            }) => {
                assert_eq!(b.source, "/h/.env");
                assert_eq!(&b.bytes[..], b"A=1\n");
            }
            _ => panic!("not parsed"),
        }
        let m = msg(parse(&req(
            OP_SECRET_ADD,
            add(json!({"path":"/h/.env","bytes_b64":"c2VjcmV0!!"})),
        )));
        assert_eq!(m, "the backup is not valid base64");
        let m = msg(parse(&req(
            OP_SECRET_ADD,
            add(json!({"path":"rel/.env","bytes_b64":"QQ=="})),
        )));
        assert_eq!(m, "the backup path must be absolute");
        let big = "A".repeat(crate::import_backup::MAX_BACKUP_BYTES / 3 * 4 + 8);
        let m = msg(parse(&req(
            OP_SECRET_ADD,
            add(json!({"path":"/h/.env","bytes_b64":big})),
        )));
        assert_eq!(m, "the backup is too large");
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

    #[test]
    fn listed_entry_must_be_the_canonical_file() {
        let real = Path::new("/usr/bin/coreutils");
        assert!(entry_is_canonical(real, real).is_ok());
        // printenv -> coreutils: the names differ.
        let e = entry_is_canonical(Path::new("/usr/bin/printenv"), real).unwrap_err();
        assert!(e.contains("differs"), "{e}");
        // Same name, a link hop in a directory.
        let e = entry_is_canonical(Path::new("/bin/coreutils"), real).unwrap_err();
        assert!(e.contains("not canonical"), "{e}");
    }

    #[test]
    fn symlinked_entry_never_grants_its_target() {
        let dir = std::env::var_os("SAIIFE_TEST_TMP")
            .map(PathBuf::from)
            .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp"));
        std::fs::create_dir_all(&dir).unwrap();
        let tmp = tempfile::tempdir_in(dir).unwrap();
        let real = std::fs::canonicalize("/bin/echo").unwrap();
        let link = tmp.path().join("echo");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // The link is listed, the client sends the canonical target.
        let r = check_exe(&real, std::slice::from_ref(&link));
        assert_eq!(r.unwrap_err().rule, "run_not_allowed");
    }
}
