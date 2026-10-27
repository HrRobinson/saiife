//! Lockdown (spec §6.18, plan 11 decision 8): one persistent flag that
//! denies connector requests (`connectors`) or also every hook call
//! (`all`). `<state>/state/lockdown.json` (0600, written atomically) holds
//! it, so it survives a restart. An unreadable file fails closed: scope
//! `all`, reason `lockdown file unreadable`.

use crate::approvers::Refusal;
use crate::ops::{now_ts, Conn, Ctx};
use saiife_audit::DecisionKind;
use saiife_broker::pipeline::{LockScope, Lockdown};
use saiife_ipc::msg::{err, err_with, ok, ErrorCode, Request};
use saiife_ipc::peer::{comm, PeerCred};
use serde_json::{json, Map, Value};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const FILE_NAME: &str = "lockdown.json";
/// The reason of the fail-closed flag.
pub const UNREADABLE: &str = "lockdown file unreadable";
/// The reason when `<state>/state` is a symlink, not ours or not 0700.
pub const UNSAFE_DIR: &str = "lockdown dir unsafe";
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
        let closed = |reason: &str, e: io::Error| {
            (
                Some(Lockdown {
                    scope: LockScope::All,
                    reason: reason.into(),
                    by_uid: 0,
                    since: now_ts(),
                }),
                Some(format!("{reason}: {e}")),
            )
        };
        let (cur, why) = match check_parent(&path) {
            Err(e) => closed(UNSAFE_DIR, e),
            Ok(()) => match read(&path) {
                Ok(l) => (l, None),
                Err(e) => closed(UNREADABLE, e),
            },
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
        self.set_if(next, |_| true)
            .expect("an unconditional change always applies")
    }

    /// [`Store::set`] only if `ok` accepts the flag as it is at the moment
    /// of the change (checked under the change lock, so no other change
    /// slips in between); `None` when it refused and nothing changed.
    pub fn set_if(
        &self,
        next: Option<Lockdown>,
        ok: impl FnOnce(Option<&Lockdown>) -> bool,
    ) -> Option<io::Result<()>> {
        let _one = lock(&self.change);
        if !ok(lock(&self.cur).as_ref()) {
            return None;
        }
        let saved = match (&self.path, &next) {
            (None, _) => Ok(()),
            (Some(p), Some(l)) => write(p, l),
            (Some(p), None) => remove(p),
        };
        if saved.is_ok() || next.is_some() {
            *lock(&self.cur) = next;
        }
        Some(saved)
    }
}

/// The dir holding the flag file: a real directory, ours, not group- or world-writable. A
/// missing dir is fine (the flag is off). Nothing is created or fixed.
pub(crate) fn check_parent(file: &Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let Some(dir) = file.parent() else {
        return Ok(());
    };
    let md = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if !md.file_type().is_dir() {
        return Err(io::Error::other(format!(
            "{} is not a directory",
            dir.display()
        )));
    }
    if md.uid() != rustix::process::geteuid().as_raw() {
        return Err(io::Error::other(format!(
            "{} is not owned by this user",
            dir.display()
        )));
    }
    // Not writable by group or others (the rule of `check_state_paths`).
    if md.permissions().mode() & 0o022 != 0 {
        return Err(io::Error::other(format!(
            "{} is writable by group or others",
            dir.display()
        )));
    }
    Ok(())
}

/// What a denied hook, lease or token says.
pub fn message(l: &Lockdown) -> String {
    format!("saiife lockdown is on: {}", l.reason)
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
    saiife_audit::mask::mask(s)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_REASON_CHARS)
        .collect()
}

/// The polkit `--detail request` of `lockdown off`.
pub const OFF_DETAIL: &str = "lockdown off";
/// The polkit `--detail request` of narrowing or replacing an active
/// lockdown.
pub const CHANGE_DETAIL: &str = "lockdown change";

/// What an approver who is not an admin may do without re-authentication:
/// turn lockdown on when it is off, or widen it (`connectors` to `all`).
/// Anything else (off, narrowing, replacing an active lockdown, even with
/// the same scope and a new reason) could weaken the kill switch, so it
/// is as strong as turning it off.
pub fn free_change(cur: Option<&Lockdown>, next: Option<LockScope>) -> bool {
    match (cur, next) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(c), Some(n)) => c.scope == LockScope::Connectors && n == LockScope::All,
    }
}

/// May the approver `conn` (not an admin) turn lockdown off? Lockdown has
/// no requester, so the approver is treated as deciding its own request:
/// under `same_user = "deny"` it is refused (`reauth_required`), under
/// `"reauth"` it must pass polkit re-authentication (an unavailable one
/// refuses). Runs off the runtime thread (the prompt can take 120 s).
async fn may_turn_off(ctx: &Arc<Ctx>, conn: &Conn, detail: &'static str) -> Result<(), Refusal> {
    let Some(cfg) = ctx.policy().system.map(|s| s.approval.clone()) else {
        return Err(Refusal::NotApprover);
    };
    let Some(name) = ctx.name_of(conn.peer.uid).await else {
        return Err(Refusal::NotApprover);
    };
    let c = Arc::clone(ctx);
    let peer = conn.peer;
    let start = conn.start_time;
    tokio::task::spawn_blocking(move || {
        // Without the caller's start time re-authentication cannot run
        // (fail closed); `same_user = "deny"` refuses before it matters.
        let no_start = crate::approval_ops::NoStartTime(c.reauth.as_ref());
        let reauth: &dyn crate::reauth::Reauth = match start {
            Some(_) => c.reauth.as_ref(),
            None => &no_start,
        };
        crate::approvers::may_decide(
            &cfg,
            c.directory.as_ref(),
            &name,
            peer.uid,
            reauth,
            &peer,
            start.unwrap_or(0),
            c.proc.as_ref(),
            &c.reauth_cooldowns,
            detail,
        )
    })
    .await
    .unwrap_or_else(|e| Err(Refusal::ReauthError(e.to_string())))
}

/// The rule and message of a refused `lockdown off` (or change of an
/// active lockdown) by an approver.
fn off_refusal(r: &Refusal, what: &str) -> (&'static str, String) {
    match r {
        Refusal::SameUserDenied => (
            "reauth_required",
            format!("{what} needs root, an [admin] group, or an approver who re-authenticates (same_user = \"reauth\")"),
        ),
        other => (other.rule(), other.to_string()),
    }
}

/// `lockdown.set {on, scope?, reason?}`. Root and `[admin] groups` may do
/// anything. An approver may turn it on when it is off or widen it
/// (`connectors` to `all`); turning it off, narrowing it or replacing an
/// active lockdown needs polkit re-authentication (`same_user = "reauth"`),
/// since weakening the kill switch is as strong as approving. Everyone else
/// gets `forbidden` and a `lockdown` record with decision `deny`.
pub async fn set(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value {
    let id = req.id;
    let peer: &PeerCred = &conn.peer;
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

    let admin = ctx.is_admin(peer.uid).await;
    let allowed = admin || crate::approval_ops::is_approver(ctx, peer.uid).await;
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
        rec.reason = Some(reason.clone());
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
    let next_scope = on.then_some(scope);
    // An approver's free change is checked against the flag at the moment
    // it is applied; if the flag moved meanwhile (or the change was never
    // free) it needs re-authentication like `off`.
    let mut reauthed = admin;
    let saved = loop {
        if !reauthed && !free_change(ctx.lockdown.get().as_ref(), next_scope) {
            let (detail, what) = if on {
                (CHANGE_DETAIL, "narrowing or replacing an active lockdown")
            } else {
                (OFF_DETAIL, "lockdown off")
            };
            if let Err(r) = may_turn_off(ctx, conn, detail).await {
                let (rule, why) = off_refusal(&r, what);
                rec.decision = DecisionKind::Deny;
                rec.rule = Some(rule.into());
                rec.reason = Some(why.clone());
                if let Err(e) = ctx.writer.append(rec).await {
                    eprintln!("saiifed: warning: cannot write lockdown record: {e}");
                }
                let mut m = Map::new();
                m.insert("rule".into(), rule.into());
                return err_with(
                    id,
                    ErrorCode::Forbidden,
                    &format!("refused ({rule}): {why}"),
                    m,
                );
            }
            reauthed = true;
        }
        let c = Arc::clone(ctx);
        let n = next.clone();
        let free = reauthed;
        let r = tokio::task::spawn_blocking(move || {
            c.lockdown
                .set_if(n, |cur| free || free_change(cur, next_scope))
        })
        .await
        .unwrap_or_else(|e| Some(Err(io::Error::other(e.to_string()))));
        if let Some(r) = r {
            break r;
        }
    };
    // The flag is changed (or not) before the record, as for `secret.*`.
    let mut problem = None;
    if let Err(e) = &saved {
        rec.decision = DecisionKind::Deny;
        rec.rule = Some("lockdown_not_saved".into());
        rec.extra.insert("applied".into(), on.into());
        rec.extra.insert("saved".into(), false.into());
        problem = Some(if on {
            format!("lockdown is ON but not saved; it will not survive a restart ({e})")
        } else {
            format!("lockdown is still ON: the flag file could not be removed ({e})")
        });
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
    let summary = if on {
        format!(
            "lockdown on ({}) by uid {}: {}",
            scope.as_str(),
            peer.uid,
            ctx.lockdown.get().map(|l| l.reason).unwrap_or_default()
        )
    } else {
        format!("lockdown off by uid {}", peer.uid)
    };
    ctx.notify(
        saiife_policy::Event::Lockdown,
        None,
        None,
        None,
        Some(peer.uid),
        &summary,
    );
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
    fn parent_dir_modes() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp();
        let p = path_in(d.path());
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        for (mode, ok) in [
            (0o700, true),
            (0o750, true),
            (0o755, true),
            (0o770, false),
            (0o757, false),
        ] {
            std::fs::set_permissions(p.parent().unwrap(), std::fs::Permissions::from_mode(mode))
                .unwrap();
            assert_eq!(check_parent(&p).is_ok(), ok, "{mode:o}");
            let (s, why) = Store::open(p.clone());
            assert_eq!(why.is_none(), ok, "{mode:o}");
            assert_eq!(s.get().is_none(), ok, "{mode:o}");
        }
        // A symlink is refused whatever it points at.
        let link = d.path().join("link");
        std::os::unix::fs::symlink(p.parent().unwrap(), &link).unwrap();
        assert!(check_parent(&link.join(FILE_NAME)).is_err());
    }

    #[test]
    fn free_change_is_on_from_off_or_widening_only() {
        use LockScope::{All, Connectors};
        let (all, con) = (flag(All), flag(Connectors));
        assert!(free_change(None, Some(All)));
        assert!(free_change(None, Some(Connectors)));
        assert!(free_change(Some(&con), Some(All)));
        assert!(!free_change(Some(&all), Some(Connectors)));
        assert!(!free_change(Some(&all), Some(All)));
        assert!(!free_change(Some(&con), Some(Connectors)));
        assert!(!free_change(None, None));
        assert!(!free_change(Some(&con), None));
    }

    #[test]
    fn set_if_checks_the_flag_under_the_change_lock() {
        let s = Store::memory();
        s.set(Some(flag(LockScope::All))).unwrap();
        let narrow = Some(flag(LockScope::Connectors));
        assert!(s
            .set_if(narrow, |cur| free_change(cur, Some(LockScope::Connectors)))
            .is_none());
        assert_eq!(s.get(), Some(flag(LockScope::All)));
    }

    #[test]
    fn reasons_lose_control_characters_and_are_cut() {
        assert_eq!(clean_reason("a\u{1b}[2Jb\nc"), "a [2Jb c");
        assert_eq!(clean_reason(&"x".repeat(1000)).chars().count(), 256);
    }
}
