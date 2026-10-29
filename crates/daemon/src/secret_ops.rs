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
use crate::vault::{valid_name, Entry, Kind, Vault, VaultState, Writer};
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

/// Why `secret import` is refused by the personal broker (decision 6).
pub const PERSONAL_IMPORT: &str = "personal broker: use secret add";

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
    // Decision 6: an import moves plaintext out of the agent's reach, which
    // the personal broker cannot do (the agent's uid reads the key), and its
    // backup would be a second plaintext copy in the user's own home.
    if ctx.mode == crate::ops::Mode::Personal && req.args.contains_key("backup") {
        let mut r = record(ctx, peer, event, &name).await;
        r.decision = DecisionKind::Deny;
        r.reason = Some(PERSONAL_IMPORT.into());
        if let Err(e) = ctx.writer.append(r).await {
            eprintln!("saiifed: warning: cannot write {event} record: {e}");
        }
        return err(id, ErrorCode::BadRequest, PERSONAL_IMPORT);
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
    // One change at a time; the vault's memory lock is held only to read
    // and to seal, never across the file write (connector calls read it).
    let mut w = ctx.vault.writer();
    if matches!(&*w.lock(), VaultState::Unavailable(_)) {
        return Err((
            ErrorCode::VaultUnavailable,
            format!(
                "vault cannot be read; restore it or remove {} by hand",
                ctx.vault_path.display()
            ),
        ));
    }
    // A rotated or removed secret's access token goes with it (plan 14
    // decision 8), and so does every token or session it minted, in every
    // scope (plan 15 decision 7): dropped under the writer, after the
    // change.
    let forget = match &parsed {
        Parsed::Rotate { name, .. } | Parsed::Remove { name } => Some(name.clone()),
        _ => None,
    };
    let done = run(&mut w, uid, parsed, &ctx.backup_dir);
    if let Some(name) = forget {
        ctx.oauth.forget(&name);
    }
    done
}

/// `f` of the vault in memory (it is `Ready`: checked under the writer,
/// and nothing makes a ready vault unavailable).
fn read<T>(w: &Writer<'_>, f: impl FnOnce(&Vault) -> T) -> Option<T> {
    match &*w.lock() {
        VaultState::Ready(v) => Some(f(v)),
        VaultState::Unavailable(_) => None,
    }
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
        "oauth2" => Ok(Kind::OAuth2),
        "aws" => Ok(Kind::Aws),
        "gcp_sa" => Ok(Kind::GcpSa),
        "azure_sp" => Ok(Kind::AzureSp),
        _ => Err(bad(
            "unknown kind (token, basic, header, oauth2, aws, gcp_sa or azure_sp)",
        )),
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
        Kind::OAuth2 => &saiife_broker::oauth2::FIELDS,
        Kind::Aws => &["access_key_id", "secret_access_key"],
        Kind::GcpSa => &["client_email", "private_key", "private_key_id"],
        Kind::AzureSp => &["tenant_id", "client_id", "client_secret"],
    }
}

/// The fields a kind may also carry.
fn optional_names(kind: Kind) -> &'static [&'static str] {
    match kind {
        Kind::Aws => &["session_token"],
        Kind::GcpSa => &["project_id"],
        _ => &[],
    }
}

fn all_of(s: &str, ok: impl Fn(char) -> bool) -> bool {
    !s.is_empty() && s.chars().all(ok)
}

/// `8-4-4-4-12` hex digits.
fn is_guid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && [8usize, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(n, p)| p.len() == *n && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// A DNS name with at least one dot.
fn is_domain(s: &str) -> bool {
    s.len() <= 253
        && s.contains('.')
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// The shape of one cloud field. A refusal names the field, never the value.
fn check_cloud_field(kind: Kind, name: &str, v: &str) -> Result<(), Refusal> {
    let ok = match name {
        "access_key_id" => {
            v.len() == 20
                && (v.starts_with("AKIA") || v.starts_with("ASIA"))
                && all_of(&v[4..], |c| c.is_ascii_uppercase() || c.is_ascii_digit())
        }
        "secret_access_key" => v.len() >= 16 && all_of(v, |c| c.is_ascii_graphic()),
        "session_token" => v.len() >= MIN_VALUE_BYTES && all_of(v, |c| c.is_ascii_graphic()),
        "client_email" => {
            v.matches('@').count() == 1
                && v.ends_with(".iam.gserviceaccount.com")
                && all_of(v, |c| c.is_ascii_graphic())
        }
        "private_key" => {
            let t = v.trim();
            t.starts_with("-----BEGIN ")
                && t.ends_with("PRIVATE KEY-----")
                && t.contains("PRIVATE KEY-----\n")
                && t.contains("-----END ")
        }
        "private_key_id" => all_of(v, |c| c.is_ascii_alphanumeric()) && v.len() >= 4,
        "project_id" => {
            v.len() <= 128
                && all_of(v, |c| {
                    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '.' | ':')
                })
        }
        "tenant_id" => is_guid(v) || is_domain(v),
        "client_id" if kind == Kind::AzureSp => is_guid(v),
        _ => true,
    };
    if ok {
        Ok(())
    } else {
        Err(bad(format!("{name} is not in the expected form")))
    }
}

/// Fields whose value may be as short as one byte: a user name or a client
/// id is not a secret.
fn short_ok(name: &str) -> bool {
    name == "username" || name == "client_id"
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
        // A PEM key has line breaks; nothing else may.
        let nl_ok = k == "private_key";
        if s.bytes()
            .any(|b| (b < 0x20 && !(nl_ok && b == b'\n')) || b == 0x7f)
        {
            return Err(bad("secret value has control characters"));
        }
        out.insert(k.clone(), Zeroizing::new(s.to_string()));
    }
    Ok(out)
}

/// Exactly the kind's fields, each long enough.
fn check_fields(kind: Kind, fields: &BTreeMap<String, Zeroizing<String>>) -> Result<(), Refusal> {
    let want = field_names(kind);
    let opt = optional_names(kind);
    if !want.iter().all(|w| fields.contains_key(*w))
        || !fields
            .keys()
            .all(|k| want.contains(&k.as_str()) || opt.contains(&k.as_str()))
    {
        let mut names = want.join(", ");
        if !opt.is_empty() {
            names = format!("{names} (optional: {})", opt.join(", "));
        }
        return Err(bad(format!("this kind takes the fields {names}")));
    }
    for (k, v) in fields {
        let min = if short_ok(k) { 1 } else { MIN_VALUE_BYTES };
        if v.len() < min {
            return Err(bad("secret value is too short"));
        }
        check_cloud_field(kind, k, v)?;
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
    vault: &mut Writer<'_>,
    uid: u32,
    p: Parsed,
    backup_dir: &Path,
) -> Result<Map<String, Value>, Refusal> {
    let io = |_e: std::io::Error| (ErrorCode::Internal, "cannot write the vault".to_string());
    match p {
        Parsed::List => {
            let secrets: Vec<Value> = read(vault, Vault::list)
                .unwrap_or_default()
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
            if read(vault, |v| v.get(&name).is_some()).unwrap_or(false) {
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
            let Some(old) = read(vault, |v| v.get(&name).cloned()).flatten() else {
                return Err(bad(format!("no secret named {name}")));
            };
            check_fields(old.kind, &fields)?;
            let mut e = old;
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
pub(crate) const MAX_EXE_BYTES: usize = 4096;

/// A refused lease: the rule and why.
pub(crate) struct Deny {
    pub(crate) rule: &'static str,
    pub(crate) detail: String,
}

fn deny(rule: &'static str, detail: impl Into<String>) -> Deny {
    Deny {
        rule,
        detail: detail.into(),
    }
}

/// `secret.lease {name, exe}`: the value of secret `name` for one command,
/// only when the caller is in a scope, the secret serves one of its
/// services (`allowed_services`), and `exe` is a listed, root-owned,
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
    // Under any lockdown scope no secret value is handed out.
    let verdict = if let Some(l) = ctx.lockdown.get() {
        Err(deny("lockdown", crate::lockdown::message(&l)))
    } else {
        match check_lease(ctx, peer.uid, &name, &exe).await {
            Ok(services) => take_value(ctx, &name, services).await,
            Err(d) => Err(d),
        }
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
                    Kind::OAuth2 => "oauth2",
                    Kind::Aws => "aws",
                    Kind::GcpSa => "gcp_sa",
                    Kind::AzureSp => "azure_sp",
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

/// The secret serves a service of the caller's scope.
fn serves_scope(e: &Entry, scope_services: &[String]) -> bool {
    e.allowed_services
        .iter()
        .any(|s| scope_services.iter().any(|x| x == s))
}

fn out_of_scope() -> Deny {
    deny(
        "no_scope",
        "the secret serves no service of the caller's scope",
    )
}

/// Scope (the caller's, and the secret's services within it), then the
/// executable. Returns the scope's services.
async fn check_lease(ctx: &Arc<Ctx>, uid: u32, name: &str, exe: &str) -> Result<Vec<String>, Deny> {
    let Some(sys) = ctx.policy().system else {
        return Err(deny("run_not_allowed", "no valid policy is loaded"));
    };
    let Some(user) = ctx.name_of(uid).await else {
        return Err(deny("no_scope", "the caller has no user name"));
    };
    let dir = Arc::clone(&ctx.directory);
    let cfg = Arc::clone(&sys);
    let scope = tokio::task::spawn_blocking(move || {
        scope_for(&cfg, dir.as_ref(), &user).map(|s| s.map(|s| s.services.clone()))
    })
    .await
    .map_err(|_| deny("run_not_allowed", "scope lookup failed"))?;
    let services = match scope {
        Ok(Some(services)) => services,
        Ok(None) => return Err(deny("no_scope", "the caller is in no scope")),
        Err(_) => {
            return Err(deny(
                "scope_conflict",
                "the caller is in more than one scope",
            ))
        }
    };
    // Memory only. A missing secret or an unavailable vault is refused
    // when the value is taken.
    if let VaultState::Ready(v) = &*ctx.vault.lock() {
        if v.get(name).is_some_and(|e| !serves_scope(e, &services)) {
            return Err(out_of_scope());
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
        .map_err(|_| deny("run_not_allowed", "executable check failed"))??;
    Ok(services)
}

/// A listed entry must be the canonical file itself: no symlink hop
/// anywhere in it, and (so) the same basename. A multi-call binary reached
/// through a link (`printenv` -> `coreutils`) therefore needs the real file
/// listed.
pub(crate) fn entry_is_canonical(entry: &Path, canonical: &Path) -> Result<(), &'static str> {
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
pub(crate) fn check_exe(exe: &Path, allow: &[PathBuf]) -> Result<(), Deny> {
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
/// The secret must still serve a service of the caller's scope (checked
/// again here, under the same lock that reads the value).
async fn take_value(
    ctx: &Arc<Ctx>,
    name: &str,
    scope_services: Vec<String>,
) -> Result<(Zeroizing<String>, Kind), Deny> {
    let c = Arc::clone(ctx);
    let n = name.to_string();
    tokio::task::spawn_blocking(move || {
        let mut guard = c.vault.lock();
        let vault = match &mut *guard {
            VaultState::Ready(v) => v,
            VaultState::Unavailable(_) => {
                return Err(deny("vault_unavailable", "the vault cannot be read"))
            }
        };
        let Some(e) = vault.get(&n) else {
            return Err(deny("unknown_secret", "no such secret"));
        };
        if !serves_scope(e, &scope_services) {
            return Err(out_of_scope());
        }
        let field = |k: &str| e.fields.get(k).map(|v| v.as_str()).unwrap_or("");
        let value = match e.kind {
            Kind::Token => Zeroizing::new(field("token").to_string()),
            Kind::Basic => Zeroizing::new(format!("{}:{}", field("username"), field("password"))),
            Kind::Header => Zeroizing::new(field("value").to_string()),
            // A refresh token is never handed out: only the daemon uses it.
            Kind::OAuth2 => {
                return Err(deny(
                    "run_not_allowed",
                    "an oauth2 secret is for connectors only",
                ))
            }
            // The daemon signs or mints with these; the lease for them is
            // `cloud.lease` (Task 10).
            Kind::Aws | Kind::GcpSa | Kind::AzureSp => {
                return Err(deny(
                    "run_not_allowed",
                    "a cloud secret is for connectors only",
                ))
            }
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
        let bogus = json!({"name":"a1","kind":"nope","fields":{},"allowed_services":["s"]});
        assert!(msg(parse(&req(OP_SECRET_ADD, bogus))).starts_with("unknown kind"));
        let oauth = json!({"name":"a1","kind":"oauth2","fields":{
            "client_id":"c","client_secret":"cs-1234","refresh_token":"rt-1234"},"allowed_services":["s"]});
        assert_eq!(msg(parse(&req(OP_SECRET_ADD, oauth))), "ok");
        let oauth = json!({"name":"a1","kind":"oauth2","fields":{
            "client_id":"c","client_secret":"cs-1234"},"allowed_services":["s"]});
        let m = msg(parse(&req(OP_SECRET_ADD, oauth)));
        assert_eq!(
            m,
            "this kind takes the fields client_id, client_secret, refresh_token"
        );
        let oauth = json!({"name":"a1","kind":"oauth2","fields":{
            "client_id":"c","client_secret":"cs1","refresh_token":"rt-1234"},"allowed_services":["s"]});
        assert_eq!(
            msg(parse(&req(OP_SECRET_ADD, oauth))),
            "secret value is too short"
        );
        let nonstr = json!({"name":"a1","kind":"token","fields":{"token":12345678},"allowed_services":["s"]});
        assert_eq!(
            msg(parse(&req(OP_SECRET_ADD, nonstr))),
            "fields must be an object of strings"
        );
    }

    fn add(kind: &str, fields: Value) -> String {
        let a = json!({"name":"c1","kind":kind,"fields":fields,"allowed_services":["s"]});
        msg(parse(&req(OP_SECRET_ADD, a)))
    }

    const AKID: &str = concat!("AKI", "A", "TESTTESTTEST0001");
    const ASKEY: &str = concat!("test-secret-", "access-key-0001");

    #[test]
    fn aws_fields_checked() {
        let ok = json!({"access_key_id": AKID, "secret_access_key": ASKEY});
        assert_eq!(add("aws", ok), "ok");
        let sts = AKID.replace("AKIA", "ASIA");
        let tok = concat!("session-", "token-value-0001");
        let ok = json!({"access_key_id": sts, "secret_access_key": ASKEY, "session_token": tok});
        assert_eq!(add("aws", ok), "ok");
        // A key id of the wrong shape: lower case, short, another prefix.
        for bad in [
            AKID.to_lowercase(),
            AKID[..19].to_string(),
            AKID.replace("AKIA", "AIDA"),
            format!("{AKID}X"),
        ] {
            let m = add(
                "aws",
                json!({"access_key_id": bad, "secret_access_key": ASKEY}),
            );
            assert_eq!(m, "access_key_id is not in the expected form");
        }
        // Missing, extra and empty fields.
        let m = add("aws", json!({"access_key_id": AKID}));
        assert!(m.contains("access_key_id, secret_access_key"), "{m}");
        let m = add(
            "aws",
            json!({"access_key_id": AKID, "secret_access_key": ASKEY, "region": "eu-west-1"}),
        );
        assert!(m.starts_with("this kind takes the fields"), "{m}");
        let m = add(
            "aws",
            json!({"access_key_id": AKID, "secret_access_key": ASKEY, "session_token": ""}),
        );
        assert_eq!(m, "secret value is too short");
    }

    #[test]
    fn gcp_fields_checked() {
        let pem = concat!(
            "-----BEGIN ",
            "PRIVATE KEY-----\nTESTBODYTESTBODY0001\n-----END ",
            "PRIVATE KEY-----\n"
        );
        let ok = json!({"client_email": "sa@p.iam.gserviceaccount.com", "private_key": pem,
            "private_key_id": "abcd1234", "project_id": "my-proj-1"});
        assert_eq!(add("gcp_sa", ok), "ok");
        for (k, bad) in [
            ("client_email", "sa@example.com"),
            ("private_key", "not a pem at all"),
            ("project_id", "Bad Project"),
        ] {
            let mut f = json!({"client_email": "sa@p.iam.gserviceaccount.com",
                "private_key": pem, "private_key_id": "abcd1234"});
            f[k] = json!(bad);
            let m = add("gcp_sa", f);
            assert_eq!(m, format!("{k} is not in the expected form"));
            assert!(!m.contains(bad));
        }
        // Line breaks are allowed in the key and nowhere else.
        let f = json!({"client_email": "sa@p.iam.gserviceaccount.com\n", "private_key": pem,
            "private_key_id": "abcd1234"});
        assert_eq!(add("gcp_sa", f), "secret value has control characters");
    }

    #[test]
    fn azure_ids_checked() {
        let g = "0123abcd-4567-89ab-cdef-0123456789ab";
        let cs = concat!("client-", "secret-0001");
        assert_eq!(
            add(
                "azure_sp",
                json!({"tenant_id": g, "client_id": g, "client_secret": cs})
            ),
            "ok"
        );
        // The tenant may be a domain; the client id may not.
        assert_eq!(
            add(
                "azure_sp",
                json!({"tenant_id": "contoso.onmicrosoft.com", "client_id": g, "client_secret": cs})
            ),
            "ok"
        );
        for (k, bad) in [
            ("tenant_id", "not-a-guid"),
            ("tenant_id", "-bad.example.com"),
            ("client_id", "contoso.onmicrosoft.com"),
            ("client_id", "0123abcd-4567-89ab-cdef-0123456789a"),
            ("client_id", "0123abcd-4567-89ab-cdef-0123456789zz"),
        ] {
            let mut f = json!({"tenant_id": g, "client_id": g, "client_secret": cs});
            f[k] = json!(bad);
            let m = add("azure_sp", f);
            assert_eq!(m, format!("{k} is not in the expected form"), "{bad}");
        }
    }

    #[test]
    fn cloud_values_never_in_records_or_errors() {
        // Every refusal names the field and never quotes a value.
        let sk = concat!("leaky-", "secret-key-0001");
        let tok = concat!("leaky-", "session-0001");
        let cases = [
            (
                "aws",
                json!({"access_key_id": "bad-id-leaky", "secret_access_key": sk, "session_token": tok}),
            ),
            (
                "aws",
                json!({"access_key_id": AKID, "secret_access_key": sk, "extra": tok}),
            ),
            (
                "gcp_sa",
                json!({"client_email": "x@leaky.example", "private_key": sk, "private_key_id": tok}),
            ),
            (
                "azure_sp",
                json!({"tenant_id": "leaky", "client_id": tok, "client_secret": sk}),
            ),
        ];
        for (kind, f) in cases {
            let m = add(kind, f);
            assert_ne!(m, "ok");
            for v in ["leaky", sk, tok] {
                assert!(!m.contains(v), "{m}");
            }
        }
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
