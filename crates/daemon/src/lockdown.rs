//! Lockdown (spec §6.18, plan 11 decision 8): one persistent flag that
//! denies connector requests (`connectors`) or also every hook call
//! (`all`). `<state>/state/lockdown.json` (0600, written atomically) holds
//! it, so it survives a restart. An unreadable file fails closed: scope
//! `all`, reason `lockdown file unreadable`.

use crate::ops::{now_ts, Ctx};
use saiife_audit::DecisionKind;
use saiife_broker::pipeline::{LockScope, Lockdown};
use saiife_ipc::msg::{err, ok, ErrorCode, Request};
use saiife_ipc::peer::{comm, PeerCred};
use serde_json::{json, Map, Value};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const FILE_NAME: &str = "lockdown.json";
/// The reason of the fail-closed flag.
pub const UNREADABLE: &str = "lockdown file unreadable";
/// The longest reason kept, in characters.
const MAX_REASON_CHARS: usize = 256;
const MAX_FILE_BYTES: u64 = 16 * 1024;

/// `<state_dir>/state/lockdown.json`.
pub fn path_in(state_dir: &Path) -> PathBuf {
    state_dir.join("state").join(FILE_NAME)
}

/// The flag in memory (what every request reads) and on disk.
pub struct Store {
    path: Option<PathBuf>,
    cur: Mutex<Option<Lockdown>>,
    /// One change at a time (file and memory move together).
    change: Mutex<()>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Store {
    /// No file: tests that never restart.
    pub fn memory() -> Store {
        Store {
            path: None,
            cur: Mutex::new(None),
            change: Mutex::new(()),
        }
    }

    /// Reads the file. Missing is off; anything else that is not a valid
    /// flag is `all` (fail closed), and the second value says why, for the
    /// start record.
    pub fn open(path: PathBuf) -> (Store, Option<String>) {
        let (cur, why) = match read(&path) {
            Ok(l) => (l, None),
            Err(e) => (
                Some(Lockdown {
                    scope: LockScope::All,
                    reason: UNREADABLE.into(),
                    by_uid: 0,
                    since: now_ts(),
                }),
                Some(format!("{UNREADABLE}: {e}")),
            ),
        };
        (
            Store {
                path: Some(path),
                cur: Mutex::new(cur),
                change: Mutex::new(()),
            },
            why,
        )
    }

    pub fn get(&self) -> Option<Lockdown> {
        lock(&self.cur).clone()
    }

    /// Turns the flag on or off. Turning on takes effect even when the
    /// file cannot be written (then `Err` says so); turning off happens
    /// only once the file is gone.
    pub fn set(&self, next: Option<Lockdown>) -> io::Result<()> {
        let _one = lock(&self.change);
        let saved = match (&self.path, &next) {
            (None, _) => Ok(()),
            (Some(p), Some(l)) => write(p, l),
            (Some(p), None) => remove(p),
        };
        if saved.is_ok() || next.is_some() {
            *lock(&self.cur) = next;
        }
        saved
    }
}

fn read(path: &Path) -> io::Result<Option<Lockdown>> {
    let f = match crate::vault::open_regular(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut b = Vec::new();
    f.take(MAX_FILE_BYTES + 1).read_to_end(&mut b)?;
    if b.len() as u64 > MAX_FILE_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "too large"));
    }
    serde_json::from_slice(&b)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("corrupt: {e}")))
}

fn write(file: &Path, l: &Lockdown) -> io::Result<()> {
    let dir = file
        .parent()
        .ok_or_else(|| io::Error::other("the lockdown file has no directory"))?;
    crate::vault::check_dir(dir, true)?;
    let bytes = serde_json::to_vec(l).map_err(io::Error::other)?;
    let tmp = dir.join(format!(".{FILE_NAME}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let staged = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, file)
    })();
    if let Err(e) = staged {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::File::open(dir)?.sync_all()
}

fn remove(file: &Path) -> io::Result<()> {
    match std::fs::remove_file(file) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    }
    match file.parent() {
        Some(d) => std::fs::File::open(d)?.sync_all(),
        None => Ok(()),
    }
}

/// The flag as the `status` answer shows it: an object, or `null`.
pub fn status_json(l: Option<&Lockdown>) -> Value {
    match l {
        Some(l) => json!({
            "scope": l.scope.as_str(),
            "reason": l.reason,
            "by_uid": l.by_uid,
            "since": l.since,
        }),
        None => Value::Null,
    }
}

/// A reason as stored: control characters become spaces, at most
/// [`MAX_REASON_CHARS`] characters.
fn clean_reason(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_REASON_CHARS)
        .collect()
}

/// Who may approve (`[approval] approvers`: user names and `group:<name>`).
/// A local helper until the approval module's own check replaces it. Any
/// lookup failure is no.
async fn is_approver(ctx: &Ctx, uid: u32) -> bool {
    let approvers = match ctx.policy().system {
        Some(s) => s.approval.approvers.clone(),
        None => return false,
    };
    if approvers.is_empty() {
        return false;
    }
    let Some(name) = ctx.name_of(uid).await else {
        return false;
    };
    let mut groups: Option<Vec<String>> = None;
    for a in &approvers {
        match a.strip_prefix("group:") {
            Some(g) => {
                if groups.is_none() {
                    groups = Some(ctx.groups_of(&name).await);
                }
                if groups.iter().flatten().any(|x| x == g) {
                    return true;
                }
            }
            None if *a == name => return true,
            None => {}
        }
    }
    false
}

/// `lockdown.set {on, scope?, reason?}`: root, `[admin] groups` and
/// approvers only. Everyone else gets `forbidden` and a `lockdown` record
/// with decision `deny`.
pub async fn set(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    let id = req.id;
    let Some(on) = req.args.get("on").and_then(Value::as_bool) else {
        return err(
            id,
            ErrorCode::BadRequest,
            "lockdown.set takes on: true|false",
        );
    };
    let scope = match req.args.get("scope") {
        None | Some(Value::Null) => LockScope::All,
        Some(Value::String(s)) if s == "all" => LockScope::All,
        Some(Value::String(s)) if s == "connectors" => LockScope::Connectors,
        Some(_) => {
            return err(
                id,
                ErrorCode::BadRequest,
                "scope is \"all\" or \"connectors\"",
            )
        }
    };
    let reason = match req.args.get("reason") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => clean_reason(s),
        Some(_) => return err(id, ErrorCode::BadRequest, "reason is a string"),
    };
    let action = if on { "on" } else { "off" };

    let allowed = ctx.is_admin(peer.uid).await || is_approver(ctx, peer.uid).await;
    let mut rec = ctx.record("lockdown", action);
    rec.uid = Some(peer.uid);
    rec.user = ctx.name_of(peer.uid).await;
    rec.extra.insert("action".into(), action.into());
    rec.extra.insert(
        "peer".into(),
        json!({"pid": peer.pid, "comm": comm(peer.pid)}),
    );
    if on {
        rec.extra.insert("scope".into(), scope.as_str().into());
        rec.reason = Some(saiife_audit::mask::mask(&reason));
    }
    if !allowed {
        rec.decision = DecisionKind::Deny;
        rec.rule = Some("forbidden".into());
        rec.reason = Some("not an admin or an approver".into());
        if let Err(e) = ctx.writer.append(rec).await {
            eprintln!("saiifed: warning: cannot write lockdown record: {e}");
        }
        return err(
            id,
            ErrorCode::Forbidden,
            "lockdown is for root, [admin] groups and [approval] approvers",
        );
    }

    let next = on.then(|| Lockdown {
        scope,
        reason,
        by_uid: peer.uid,
        since: now_ts(),
    });
    let c = Arc::clone(ctx);
    let saved = tokio::task::spawn_blocking(move || c.lockdown.set(next))
        .await
        .unwrap_or_else(|e| Err(io::Error::other(e.to_string())));
    // The flag is changed (or not) before the record, as for `secret.*`.
    let mut problem = None;
    if let Err(e) = &saved {
        rec.decision = DecisionKind::Deny;
        rec.rule = Some("lockdown_not_saved".into());
        problem = Some(format!(
            "lockdown {action}: the flag file could not be written: {e}"
        ));
    }
    let recorded = ctx.writer.append(rec).await;
    if let Some(m) = problem {
        return err(id, ErrorCode::Internal, &m);
    }
    if let Err(e) = recorded {
        return err(
            id,
            ErrorCode::Unrecorded,
            &format!("lockdown {action} is set, but its record could not be written: {e}"),
        );
    }
    let mut m = Map::new();
    m.insert("lockdown".into(), status_json(ctx.lockdown.get().as_ref()));
    ok(id, m)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn flag(scope: LockScope) -> Lockdown {
        Lockdown {
            scope,
            reason: "r".into(),
            by_uid: 7,
            since: "t".into(),
        }
    }

    #[test]
    fn set_survives_reopen_and_off_removes() {
        let d = tmp();
        let p = path_in(d.path());
        let (s, why) = Store::open(p.clone());
        assert!(why.is_none() && s.get().is_none());
        s.set(Some(flag(LockScope::Connectors))).unwrap();
        let (s2, why) = Store::open(p.clone());
        assert!(why.is_none());
        assert_eq!(s2.get(), Some(flag(LockScope::Connectors)));
        s2.set(None).unwrap();
        assert!(!p.exists());
        assert!(Store::open(p).0.get().is_none());
    }

    #[test]
    fn corrupt_file_is_all() {
        let d = tmp();
        let p = path_in(d.path());
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"{not json").unwrap();
        let (s, why) = Store::open(p);
        let l = s.get().unwrap();
        assert_eq!((l.scope, l.reason.as_str()), (LockScope::All, UNREADABLE));
        assert!(why.unwrap().starts_with(UNREADABLE));
    }

    #[test]
    fn reasons_lose_control_characters_and_are_cut() {
        assert_eq!(clean_reason("a\u{1b}[2Jb\nc"), "a [2Jb c");
        assert_eq!(clean_reason(&"x".repeat(1000)).chars().count(), 256);
    }
}
