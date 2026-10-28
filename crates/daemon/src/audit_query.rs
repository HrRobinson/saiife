//! `audit.query` (spec §6.4.5, §8.7): the audit log for users who cannot
//! read the files. A caller gets only the records that carry its own uid,
//! of the kinds `guard`, `connector` and `approval`; a record without a uid
//! is never returned. `all: true` returns every record and needs root or a
//! member of `saiife-audit`, checked on the current groups at each request
//! (decision 6: no cache). The uid scope comes first; the filters only
//! narrow it.
//!
//! Records come in log order (month file, then line), at most `limit`
//! (≤ 5000) and at most [`MAX_ANSWER_BYTES`] of JSON per answer, so an
//! answer always fits the control socket's 16 MiB frame. `more` says there
//! are further matches: ask again with `after = next`. `next` is an opaque
//! position in the log (month file and line), so paging stays exact when a
//! chain restarts and seqs repeat. `after_seq` (answered by `next_seq`)
//! still works, but only on a log with a single chain. Records without a
//! `seq` (v1 lines) are not returned.

use crate::ops::Ctx;
use saiife_audit::store::{self, Filter};
use saiife_audit::Record;
use saiife_ipc::msg::{err, ok, ErrorCode, Request};
use saiife_ipc::peer::PeerCred;
use saiife_policy::Directory;
use serde_json::{json, Map, Value};
use std::path::Path;
use std::sync::Arc;
use time::OffsetDateTime;

/// The group that may read the whole audit log (spec §5.2).
pub use saiife_system::layout::AUDIT_GROUP;
/// Queries reading the log at once, daemon-wide: each reads month files
/// from disk, so a burst of them must not multiply the memory and I/O.
pub const MAX_CONCURRENT: usize = 2;
static QUERIES: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(MAX_CONCURRENT);
/// Most records in one answer.
pub const MAX_LIMIT: u64 = 5000;
/// Most bytes of record JSON in one answer: half the 16 MiB answer frame,
/// so the envelope and JSON escaping never push it over.
pub const MAX_ANSWER_BYTES: usize = 8 * 1024 * 1024;
/// The kinds a caller sees of its own records.
pub const USER_KINDS: [&str; 3] = ["guard", "connector", "approval"];
/// Longest filter string.
const MAX_FILTER: usize = 4096;

/// Whose records a query may see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The records of this uid, of [`USER_KINDS`].
    Uid(u32),
    /// Every record (auditors and root).
    All,
}

/// A parsed `audit.query`.
#[derive(Debug, Clone, Default)]
pub struct Query {
    pub filter: Filter,
    pub kind: Option<String>,
    pub service: Option<String>,
    pub all: bool,
    pub limit: u64,
    pub after_seq: Option<u64>,
    /// Only records after this position (the previous page's `next`).
    pub after: Option<Pos>,
}

/// A record's place in the log: its month file (`YYYY-MM`) and its line
/// index in that file. Months sort as text, so this order is log order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pos {
    pub month: String,
    pub line: u64,
}

impl Pos {
    /// `YYYY-MM:<line>`, the wire form of `next` and `after`.
    pub fn cursor(&self) -> String {
        format!("{}:{}", self.month, self.line)
    }

    /// The inverse of [`Pos::cursor`]; anything else is an error.
    pub fn parse(s: &str) -> Result<Pos, String> {
        let bad = || "after must be the next value of an earlier answer".to_string();
        let (month, line) = s.split_once(':').ok_or_else(bad)?;
        let m = month.as_bytes();
        let month_ok = m.len() == 7
            && m[..4].iter().all(u8::is_ascii_digit)
            && m[4] == b'-'
            && m[5..].iter().all(u8::is_ascii_digit);
        if !month_ok || line.is_empty() || !line.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        Ok(Pos {
            month: month.to_string(),
            line: line.parse().map_err(|_| bad())?,
        })
    }
}

/// One page of the answer.
#[derive(Debug, Clone, PartialEq)]
pub struct Page {
    pub records: Vec<Value>,
    pub more: bool,
    /// The `after_seq` of the next page, when `more` (single-chain logs).
    pub next_seq: Option<u64>,
    /// The `after` of the next page, when `more`.
    pub next: Option<String>,
}

/// Root, or a member of [`AUDIT_GROUP`] by the directory's current answer.
/// Any lookup failure is "no".
pub fn may_read_all(dir: &dyn Directory, uid: u32) -> bool {
    uid == 0
        || dir
            .name_of(uid)
            .is_some_and(|n| dir.groups_of(&n).iter().any(|g| g == AUDIT_GROUP))
}

/// The scope of a query by `uid`: its own records, or with `all` every
/// record when `auditor()` says so (asked only then).
pub fn scope_for(all: bool, uid: u32, auditor: impl FnOnce() -> bool) -> Result<Scope, String> {
    if !all {
        return Ok(Scope::Uid(uid));
    }
    if auditor() {
        Ok(Scope::All)
    } else {
        Err(format!(
            "audit.query with all is for root and the {AUDIT_GROUP} group"
        ))
    }
}

fn opt_str(args: &Map<String, Value>, k: &str) -> Result<Option<String>, String> {
    match args.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.len() <= MAX_FILTER => Ok(Some(s.clone())),
        Some(Value::String(_)) => Err(format!("{k} is longer than {MAX_FILTER} bytes")),
        Some(_) => Err(format!("{k} must be a string")),
    }
}

fn opt_bool(args: &Map<String, Value>, k: &str) -> Result<bool, String> {
    match args.get(k) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(format!("{k} must be true or false")),
    }
}

fn opt_u64(args: &Map<String, Value>, k: &str) -> Result<Option<u64>, String> {
    match args.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("{k} must be a whole number")),
    }
}

/// `{since?, kind?, service?, agent?, project?, blocked?, all?, limit?,
/// after_seq?, after?}`. `since` is a Unix time in seconds; `limit` is 1..=5000
/// (default 5000).
pub fn parse(args: &Map<String, Value>) -> Result<Query, String> {
    let since = match args.get("since") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let s = v.as_i64().ok_or("since must be a Unix time in seconds")?;
            Some(
                OffsetDateTime::from_unix_timestamp(s)
                    .map_err(|_| "since is out of range".to_string())?,
            )
        }
    };
    let limit = opt_u64(args, "limit")?.unwrap_or(MAX_LIMIT);
    if limit == 0 || limit > MAX_LIMIT {
        return Err(format!("limit must be between 1 and {MAX_LIMIT}"));
    }
    Ok(Query {
        filter: Filter {
            since,
            project: opt_str(args, "project")?,
            agent: opt_str(args, "agent")?,
            blocked_only: opt_bool(args, "blocked")?,
        },
        kind: opt_str(args, "kind")?,
        service: opt_str(args, "service")?,
        all: opt_bool(args, "all")?,
        limit,
        after_seq: opt_u64(args, "after_seq")?,
        after: opt_str(args, "after")?
            .map(|a| Pos::parse(&a))
            .transpose()?,
    })
}

/// `r` is inside `scope`. A uid scope needs the record's own uid and one
/// of [`USER_KINDS`]; a record without a uid is outside every uid scope.
pub fn in_scope(r: &Record, scope: Scope) -> bool {
    match scope {
        Scope::All => true,
        Scope::Uid(uid) => r.uid == Some(uid) && USER_KINDS.contains(&r.kind()),
    }
}

/// `r` passes the query's filters (bookkeeping records never do).
pub fn matches(r: &Record, q: &Query) -> bool {
    q.filter.matches(r)
        && q.kind.as_deref().is_none_or(|k| r.kind() == k)
        && q.service
            .as_deref()
            .is_none_or(|s| r.extra.get("service").and_then(Value::as_str) == Some(s))
}

/// A record too large for any answer: its place in the chain, not its
/// content, so paging still moves on.
fn stub(r: &Record) -> Value {
    json!({
        "v": r.v,
        "seq": r.seq,
        "ts": r.ts,
        "kind": r.kind(),
        "uid": r.uid,
        "omitted": "record larger than the audit.query answer limit",
    })
}

/// [`page_at`] with each record placed by its index in `records`, all in
/// one month (for callers that hold records, not month files).
pub fn page(records: &[Record], scope: Scope, q: &Query) -> Page {
    let placed: Vec<(Pos, &Record)> = records
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let pos = Pos {
                month: "0000-00".into(),
                line: i as u64,
            };
            (pos, r)
        })
        .collect();
    page_at(&placed, scope, q)
}

/// One page of `records` (in log order, each with its place) for `scope`
/// and `q`. The scope is applied before anything else; records without a
/// `seq` are skipped.
pub fn page_at(records: &[(Pos, &Record)], scope: Scope, q: &Query) -> Page {
    let mut pager = Pager::new(scope, q);
    for (pos, r) in records {
        if pager.offer(pos, r) {
            break;
        }
    }
    pager.finish()
}

/// Builds one page from records offered one at a time, in log order, so a
/// caller can stop reading the log as soon as the page is complete.
struct Pager<'q> {
    scope: Scope,
    q: &'q Query,
    out: Vec<Value>,
    bytes: usize,
    more: bool,
    last: Option<(Pos, Option<u64>)>,
}

impl<'q> Pager<'q> {
    fn new(scope: Scope, q: &'q Query) -> Self {
        Pager {
            scope,
            q,
            out: Vec::new(),
            bytes: 0,
            more: false,
            last: None,
        }
    }

    /// Offers the record at `pos`. The scope is checked first, then the
    /// position (`after`, `after_seq`), then the filters. True when the
    /// page is complete: one more match was seen, so `more` is set and
    /// nothing after it needs reading.
    fn offer(&mut self, pos: &Pos, r: &Record) -> bool {
        if self.more {
            return true;
        }
        let q = self.q;
        if !in_scope(r, self.scope)
            || q.after.as_ref().is_some_and(|a| pos <= a)
            || !r.seq.is_some_and(|s| q.after_seq.is_none_or(|a| s > a))
            || !matches(r, q)
        {
            return false;
        }
        if self.out.len() as u64 >= q.limit {
            self.more = true;
            return true;
        }
        let mut v = serde_json::to_value(r).unwrap_or_else(|_| stub(r));
        let mut n = serde_json::to_vec(&v)
            .map(|b| b.len())
            .unwrap_or(usize::MAX);
        if n > MAX_ANSWER_BYTES {
            v = stub(r);
            n = serde_json::to_vec(&v).map(|b| b.len()).unwrap_or(0);
        }
        if self.bytes + n > MAX_ANSWER_BYTES {
            self.more = true;
            return true;
        }
        self.bytes += n;
        self.last = Some((pos.clone(), r.seq));
        self.out.push(v);
        false
    }

    fn finish(self) -> Page {
        let q = self.q;
        let (next, next_seq) = match (self.more, self.last) {
            (false, _) => (None, None),
            (true, Some((p, s))) => (Some(p.cursor()), s),
            (true, None) => (q.after.as_ref().map(Pos::cursor), q.after_seq),
        };
        Page {
            records: self.out,
            more: self.more,
            next_seq,
            next,
        }
    }
}

/// `YYYY-MM` of `t` in UTC: the first month file that can hold a record
/// at or after `t`.
fn month_of(t: OffsetDateTime) -> String {
    let t = t.to_offset(time::UtcOffset::UTC);
    format!("{:04}-{:02}", t.year(), u8::from(t.month()))
}

/// [`page_at`] over the month files in `dir`, each record placed by its
/// month file and line index. Month files entirely before `since`, or
/// before the `after` position, are not read. Each file is read a line at
/// a time and reading stops once the page is complete, so a query holds at
/// most one page and one line, whatever the size of the log.
pub fn run(dir: &Path, scope: Scope, q: &Query) -> Result<Page, String> {
    scan(dir, scope, q, &mut |_| {})
}

/// [`run`], calling `on_line` with the position of each line it reads.
fn scan(
    dir: &Path,
    scope: Scope,
    q: &Query,
    on_line: &mut dyn FnMut(&Pos),
) -> Result<Page, String> {
    use std::io::BufRead;
    let files =
        store::month_files(dir).map_err(|e| format!("the audit directory cannot be read: {e}"))?;
    let mut first = q.filter.since.map(month_of).unwrap_or_default();
    if let Some(a) = &q.after {
        first = first.max(a.month.clone());
    }
    let mut pager = Pager::new(scope, q);
    let mut line = Vec::new();
    'files: for p in files {
        let Some(month) = p.file_stem().and_then(|n| n.to_str()).map(str::to_string) else {
            continue;
        };
        if month < first {
            continue;
        }
        // A regular file only (no symlinks, no FIFOs).
        let Some(f) = store::open_regular(&p) else {
            continue; // unreadable: skipped, as store::read_all does
        };
        let mut rd = std::io::BufReader::new(f);
        let mut pos = Pos { month, line: 0 };
        loop {
            line.clear();
            match rd.read_until(b'\n', &mut line) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => break, // unreadable from here: the rest is skipped
            }
            on_line(&pos);
            // Lines up to the `after` position were answered before. A
            // half-written last line does not parse and is skipped.
            let skip = q.after.as_ref().is_some_and(|a| &pos <= a)
                || line.iter().all(u8::is_ascii_whitespace);
            if !skip {
                if let Ok(r) = serde_json::from_slice::<Record>(&line) {
                    if pager.offer(&pos, &r) {
                        break 'files;
                    }
                }
            }
            pos.line += 1;
        }
    }
    Ok(pager.finish())
}

/// The `audit.query` op.
pub async fn handle(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    let id = req.id;
    let q = match parse(&req.args) {
        Ok(q) => q,
        Err(m) => return err(id, ErrorCode::BadRequest, &m),
    };
    let uid = peer.uid;
    let auditor = if q.all {
        // Decision 6: the current groups, looked up for this request.
        let dir = Arc::clone(&ctx.directory);
        tokio::task::spawn_blocking(move || may_read_all(dir.as_ref(), uid))
            .await
            .unwrap_or(false)
    } else {
        false
    };
    let scope = match scope_for(q.all, uid, || auditor) {
        Ok(s) => s,
        Err(m) => return err(id, ErrorCode::Forbidden, &m),
    };
    let Ok(_permit) = QUERIES.acquire().await else {
        return err(id, ErrorCode::Internal, "audit.query failed");
    };
    let dir = ctx.audit_dir.clone();
    let res = tokio::task::spawn_blocking(move || run(&dir, scope, &q)).await;
    match res {
        Ok(Ok(p)) => {
            let mut m = Map::new();
            m.insert("records".into(), Value::Array(p.records));
            m.insert("more".into(), p.more.into());
            if let Some(n) = p.next_seq {
                m.insert("next_seq".into(), n.into());
            }
            if let Some(n) = p.next {
                m.insert("next".into(), n.into());
            }
            ok(id, m)
        }
        Ok(Err(e)) => err(id, ErrorCode::Unavailable, &e),
        Err(_) => err(id, ErrorCode::Internal, "audit.query failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use saiife_audit::{DecisionKind, NewRecord};
    use saiife_policy::FixedDirectory;

    const ME: u32 = 1000;
    const OTHER: u32 = 1001;

    fn rec(seq: u64, kind: &str, uid: Option<u32>, input: &str) -> Record {
        let mut r = Record::new(
            NewRecord {
                agent: "claude",
                project: "/p",
                session: None,
                tool: "Bash",
                input,
                decision: DecisionKind::Allow,
                pack: None,
                rule: None,
                reason: None,
                mode: "locked",
                policy: None,
                permission_mode: None,
            },
            "test",
        );
        r.seq = Some(seq);
        r.kind = Some(kind.into());
        r.uid = uid;
        r
    }

    fn q(args: Value) -> Query {
        parse(args.as_object().unwrap()).unwrap()
    }

    fn inputs(p: &Page) -> Vec<String> {
        p.records
            .iter()
            .map(|r| r["input"].as_str().unwrap_or("").to_string())
            .collect()
    }

    fn mixed() -> Vec<Record> {
        let mut conn = rec(3, "connector", Some(OTHER), "other-conn");
        conn.extra.insert("service".into(), "erp".into());
        let mut mine_conn = rec(4, "connector", Some(ME), "my-conn");
        mine_conn.extra.insert("service".into(), "erp".into());
        vec![
            rec(0, "genesis", None, ""),
            rec(1, "guard", Some(ME), "my-guard"),
            rec(2, "guard", Some(OTHER), "other-guard"),
            conn,
            mine_conn,
            rec(5, "approval", Some(ME), "my-approval"),
            rec(6, "approval", Some(OTHER), "other-approval"),
            rec(7, "daemon", Some(ME), "daemon-under-my-uid"),
            rec(8, "guard", None, "no-uid-guard"),
            rec(9, "connector", None, "no-uid-conn"),
        ]
    }

    #[test]
    fn non_auditor_sees_only_own_uid() {
        let p = page(&mixed(), Scope::Uid(ME), &q(json!({})));
        assert_eq!(inputs(&p), ["my-guard", "my-conn", "my-approval"]);
        assert!(p.records.iter().all(|r| r["uid"] == ME));
        assert!(!p.more);
        assert_eq!(p.next_seq, None);
        // Another uid sees only its own.
        let p = page(&mixed(), Scope::Uid(OTHER), &q(json!({})));
        assert_eq!(inputs(&p), ["other-guard", "other-conn", "other-approval"]);
    }

    #[test]
    fn records_without_uid_excluded() {
        let records = mixed();
        for scope in [Scope::Uid(ME), Scope::Uid(OTHER), Scope::Uid(0)] {
            let p = page(&records, scope, &q(json!({})));
            assert!(
                !inputs(&p).iter().any(|i| i.starts_with("no-uid")),
                "{scope:?}: {p:?}"
            );
        }
        // A filter naming such a record does not bring it in.
        let p = page(&records, Scope::Uid(ME), &q(json!({"kind": "guard"})));
        assert_eq!(inputs(&p), ["my-guard"]);
        // The auditor scope sees them (bookkeeping aside).
        let p = page(&records, Scope::All, &q(json!({})));
        assert!(inputs(&p).contains(&"no-uid-guard".to_string()));
        assert!(!p.records.iter().any(|r| r["kind"] == "genesis"));
    }

    #[test]
    fn all_requires_auditor_group() {
        let dir = FixedDirectory::from_text(
            "me:x:1000:1000::/h:/bin/sh\naud:x:1002:1002::/h:/bin/sh\nprim:x:1003:3000::/h:/bin/sh\n",
            "me:x:1000:\naud:x:1002:\nwheel:x:10:me\nsaiife-audit:x:3000:aud\n",
        );
        assert!(!may_read_all(&dir, 1000));
        assert!(may_read_all(&dir, 1002));
        // Primary group counts.
        assert!(may_read_all(&dir, 1003));
        assert!(may_read_all(&dir, 0));
        // Unknown uid: no.
        assert!(!may_read_all(&dir, 4242));

        let refused = scope_for(true, 1000, || may_read_all(&dir, 1000)).unwrap_err();
        assert_eq!(
            refused,
            "audit.query with all is for root and the saiife-audit group"
        );
        assert_eq!(
            scope_for(true, 1002, || may_read_all(&dir, 1002)),
            Ok(Scope::All)
        );
        assert_eq!(scope_for(true, 0, || may_read_all(&dir, 0)), Ok(Scope::All));
        // Without all, nobody is asked about and everyone is scoped.
        let asked = std::cell::Cell::new(false);
        let s = scope_for(false, 1002, || {
            asked.set(true);
            true
        });
        assert_eq!(s, Ok(Scope::Uid(1002)));
        assert!(!asked.get());
        // `all` must be a bool, not a truthy string.
        assert!(parse(json!({"all": "yes"}).as_object().unwrap()).is_err());
    }

    #[test]
    fn filters_apply_after_uid_scope() {
        let records = mixed();
        // A filter that matches only another user's records yields nothing.
        let p = page(&records, Scope::Uid(ME), &q(json!({"kind": "daemon"})));
        assert!(p.records.is_empty(), "{p:?}");
        let p = page(&records, Scope::Uid(ME), &q(json!({"service": "erp"})));
        assert_eq!(inputs(&p), ["my-conn"]);
        let p = page(&records, Scope::Uid(OTHER), &q(json!({"service": "erp"})));
        assert_eq!(inputs(&p), ["other-conn"]);
        let p = page(
            &records,
            Scope::Uid(ME),
            &q(json!({"project": "/p", "agent": "claude"})),
        );
        assert_eq!(inputs(&p), ["my-guard", "my-conn", "my-approval"]);
        let p = page(
            &records,
            Scope::Uid(ME),
            &q(json!({"project": "/elsewhere"})),
        );
        assert!(p.records.is_empty());
        let p = page(&records, Scope::Uid(ME), &q(json!({"blocked": true})));
        assert!(p.records.is_empty());
        // since: far future hides everything; the epoch hides nothing.
        let p = page(
            &records,
            Scope::Uid(ME),
            &q(json!({"since": 4_000_000_000i64})),
        );
        assert!(p.records.is_empty());
        let p = page(&records, Scope::Uid(ME), &q(json!({"since": 0})));
        assert_eq!(p.records.len(), 3);
    }

    #[test]
    fn pagination_after_seq() {
        let records: Vec<Record> = (1..=12)
            .map(|s| {
                let uid = if s % 3 == 0 { OTHER } else { ME };
                rec(s, "guard", Some(uid), &format!("r{s}"))
            })
            .collect();
        let mut seen = Vec::new();
        let mut after: Option<u64> = None;
        let mut pages = 0;
        loop {
            let mut a = json!({"limit": 3});
            if let Some(s) = after {
                a["after_seq"] = s.into();
            }
            let p = page(&records, Scope::Uid(ME), &q(a));
            pages += 1;
            assert!(p.records.len() <= 3);
            assert!(p.records.iter().all(|r| r["uid"] == ME));
            seen.extend(inputs(&p));
            if !p.more {
                assert_eq!(p.next_seq, None);
                break;
            }
            after = p.next_seq;
            assert!(pages < 10);
        }
        assert_eq!(seen, ["r1", "r2", "r4", "r5", "r7", "r8", "r10", "r11"]);
        assert_eq!(pages, 3);
        // An after_seq that names another user's record skips nothing of ours.
        let p = page(&records, Scope::Uid(ME), &q(json!({"after_seq": 3})));
        assert_eq!(inputs(&p)[0], "r4");
        // Limits are bounded.
        for bad in [
            json!({"limit": 0}),
            json!({"limit": 5001}),
            json!({"limit": -1}),
        ] {
            assert!(parse(bad.as_object().unwrap()).is_err(), "{bad}");
        }
        assert_eq!(q(json!({})).limit, MAX_LIMIT);
        assert!(parse(json!({"after_seq": "1"}).as_object().unwrap()).is_err());
    }

    /// Pages every record of `scope` out of `dir` by the `next` cursor.
    fn page_all(dir: &Path, scope: Scope, limit: u64) -> (Vec<String>, usize) {
        let (mut seen, mut pages, mut after) = (Vec::new(), 0, None::<String>);
        loop {
            let mut a = json!({ "limit": limit });
            if let Some(c) = &after {
                a["after"] = c.clone().into();
            }
            let p = run(dir, scope, &q(a)).unwrap();
            pages += 1;
            seen.extend(inputs(&p));
            if !p.more {
                assert_eq!(p.next, None);
                break;
            }
            assert!(p.next.is_some() && p.next != after, "{p:?}");
            after = p.next;
            assert!(pages < 50);
        }
        (seen, pages)
    }

    #[test]
    fn paging_crosses_a_chain_restart() {
        // Two chains: the second restarts at seq 0, so seqs 0..=4 appear
        // twice. Every page cut, including one inside the shared seqs,
        // must return each record exactly once, in log order.
        let d = tempfile::tempdir().unwrap();
        let mut lines = Vec::new();
        let mut want = Vec::new();
        for chain in ["a", "b"] {
            lines.push(serde_json::to_string(&rec(0, "genesis", None, "")).unwrap());
            for s in 1..=4 {
                let input = format!("{chain}{s}");
                lines.push(serde_json::to_string(&rec(s, "guard", Some(ME), &input)).unwrap());
                want.push(input);
            }
        }
        std::fs::write(d.path().join("2026-09.jsonl"), lines[..7].join("\n") + "\n").unwrap();
        std::fs::write(d.path().join("2026-10.jsonl"), lines[7..].join("\n") + "\n").unwrap();
        for limit in 1..=9 {
            let (seen, _) = page_all(d.path(), Scope::Uid(ME), limit);
            assert_eq!(seen, want, "limit {limit}");
        }
        // The cut right after a2 (seq 2) still brings b1 and b2 (seqs 1
        // and 2 of the second chain), which after_seq = 2 would skip.
        let p = run(d.path(), Scope::Uid(ME), &q(json!({"limit": 2}))).unwrap();
        assert_eq!(inputs(&p), ["a1", "a2"]);
        assert_eq!(p.next_seq, Some(2));
        let next = p.next.unwrap();
        let p = run(d.path(), Scope::Uid(ME), &q(json!({"after": next}))).unwrap();
        assert_eq!(inputs(&p), ["a3", "a4", "b1", "b2", "b3", "b4"]);
        assert!(!p.more);
        // A cursor that is not one of ours is refused.
        for bad in ["", "7", "2026-10", "2026-1:3", "2026-10:x", "2026-10:-1"] {
            assert!(
                parse(json!({ "after": bad }).as_object().unwrap()).is_err(),
                "{bad}"
            );
        }
        assert!(parse(json!({"after": 3}).as_object().unwrap()).is_err());
        // A cut inside the second month file resumes there.
        let p = run(d.path(), Scope::Uid(ME), &q(json!({"limit": 8}))).unwrap();
        assert!(!p.more);
        let p = run(d.path(), Scope::Uid(ME), &q(json!({"limit": 7}))).unwrap();
        let next = p.next.unwrap();
        let p = run(d.path(), Scope::Uid(ME), &q(json!({"after": next}))).unwrap();
        assert_eq!(inputs(&p), ["b4"]);
    }

    #[test]
    fn answers_stay_under_the_byte_cap() {
        let big = "x".repeat(1024 * 1024);
        let records: Vec<Record> = (1..=20).map(|s| rec(s, "guard", Some(ME), &big)).collect();
        // Record::new truncates input; put the bulk in an extra field.
        let records: Vec<Record> = records
            .into_iter()
            .map(|mut r| {
                r.extra.insert("blob".into(), big.clone().into());
                r
            })
            .collect();
        let p = page(&records, Scope::Uid(ME), &q(json!({})));
        let n: usize = p
            .records
            .iter()
            .map(|v| serde_json::to_vec(v).unwrap().len())
            .sum();
        assert!(n <= MAX_ANSWER_BYTES, "{n}");
        assert!(p.more && !p.records.is_empty());
        assert_eq!(p.next_seq, p.records.last().unwrap()["seq"].as_u64());
        // One record over the cap comes back as a stub, so paging moves on.
        let mut huge = rec(1, "guard", Some(ME), "h");
        huge.extra
            .insert("blob".into(), "y".repeat(MAX_ANSWER_BYTES + 1).into());
        let p = page(&[huge], Scope::Uid(ME), &q(json!({})));
        assert_eq!(p.records.len(), 1);
        assert_eq!(p.records[0]["seq"], 1);
        assert!(p.records[0].get("blob").is_none());
        assert!(!p.more);
    }

    #[test]
    fn run_stops_reading_at_the_page() {
        // Three month files of 2000 lines each, a third of them another
        // user's. A page of 3 reads up to the 4th match and no further:
        // the later lines and month files are never read.
        let d = tempfile::tempdir().unwrap();
        let mut want = Vec::new();
        for month in ["2026-09", "2026-10", "2026-11"] {
            let lines: Vec<String> = (0..2000u64)
                .map(|i| {
                    let uid = if i % 3 == 1 { OTHER } else { ME };
                    let input = format!("{month}/{i}");
                    if uid == ME {
                        want.push(input.clone());
                    }
                    serde_json::to_string(&rec(i, "guard", Some(uid), &input)).unwrap()
                })
                .collect();
            std::fs::write(
                d.path().join(format!("{month}.jsonl")),
                lines.join("\n") + "\n",
            )
            .unwrap();
        }
        let read = |a: Value| {
            let mut seen = Vec::new();
            let p = scan(d.path(), Scope::Uid(ME), &q(a), &mut |pos| {
                seen.push(pos.cursor())
            })
            .unwrap();
            (p, seen)
        };
        let (p, seen) = read(json!({"limit": 3}));
        assert_eq!(inputs(&p), want[..3]);
        assert!(p.more);
        assert_eq!(p.next.as_deref(), Some("2026-09:3"));
        // Lines 0..=5: matches at 0, 2, 3 and the one more at 5.
        assert_eq!(
            seen,
            [
                "2026-09:0",
                "2026-09:1",
                "2026-09:2",
                "2026-09:3",
                "2026-09:4",
                "2026-09:5"
            ]
        );
        // A page that starts in the second month never opens the first and
        // stops long before the third.
        let (p, seen) = read(json!({"limit": 3, "after": "2026-10:1000"}));
        assert_eq!(inputs(&p), ["2026-10/1001", "2026-10/1002", "2026-10/1004"]);
        assert!(p.more);
        assert!(seen.iter().all(|c| c.starts_with("2026-10:")), "{seen:?}");
        assert_eq!(seen.last().map(String::as_str), Some("2026-10:1005"));
        assert_eq!(seen.len(), 1006);
        // The byte cap stops reading too: one record over half the cap
        // fills the page, and the next match is the last line read (of 3).
        let big = "z".repeat(MAX_ANSWER_BYTES / 2 + 1);
        let lines: Vec<String> = (0..3u64)
            .map(|i| {
                let mut r = rec(i, "guard", Some(ME), "b");
                r.extra.insert("blob".into(), big.clone().into());
                serde_json::to_string(&r).unwrap()
            })
            .collect();
        let e = tempfile::tempdir().unwrap();
        std::fs::write(e.path().join("2026-12.jsonl"), lines.join("\n") + "\n").unwrap();
        let mut n = 0;
        let p = scan(e.path(), Scope::Uid(ME), &q(json!({})), &mut |_| n += 1).unwrap();
        assert_eq!(p.records.len(), 1);
        assert!(p.more);
        assert_eq!(n, 2);
        // Paging to the end still returns every record once, in log order.
        let (all, _) = page_all(d.path(), Scope::Uid(ME), MAX_LIMIT);
        assert_eq!(all, want);
    }

    #[test]
    fn run_reads_the_month_files() {
        let d = tempfile::tempdir().unwrap();
        let lines: Vec<String> = mixed()
            .iter()
            .map(|r| serde_json::to_string(r).unwrap())
            .collect();
        std::fs::write(d.path().join("2026-10.jsonl"), lines.join("\n") + "\n").unwrap();
        let p = run(d.path(), Scope::Uid(ME), &q(json!({}))).unwrap();
        assert_eq!(inputs(&p), ["my-guard", "my-conn", "my-approval"]);
        // since skips whole month files before it (never opened: a
        // garbage older file is not even counted).
        std::fs::write(d.path().join("2020-01.jsonl"), "garbage\n").unwrap();
        let since = time::macros::datetime!(2026-01-01 00:00 UTC).unix_timestamp();
        let p = run(d.path(), Scope::Uid(ME), &q(json!({"since": since}))).unwrap();
        assert_eq!(p.records.len(), 3);
        assert_eq!(
            month_of(time::macros::datetime!(2026-03-31 23:30 -2)),
            "2026-04"
        );
        // A missing dir is no records, not an error.
        let p = run(&d.path().join("none"), Scope::Uid(ME), &q(json!({}))).unwrap();
        assert!(p.records.is_empty());
    }
}
