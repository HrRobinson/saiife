//! `saiife box diff | land | apply | push` (plan 39 Task 6), and the land
//! commit, written by the CLI as the user with git plumbing only.
//!
//! The commit (ruling R-T6a): every blob comes from `delta.bin`, re-checked
//! with `Reader::paths_only` and streamed into `git hash-object -w
//! --no-filters --stdin` (never a path in the user's tree, so no box-written
//! `.gitattributes` or filter acts); the tree is the parent's, read into a
//! private temporary index (`GIT_INDEX_FILE`), changed with `update-index
//! -z --index-info`, written with `write-tree` and checked against what the
//! delta says it must be; then `commit-tree -p <parent> -F -`. Every git call
//! runs with hooks and fsmonitor off and git's NTFS/HFS path checks on
//! (`box_repo::git_cmd`).
//!
//! Only refs move (R-T6d): saiife never checks out or merges box content,
//! so no filter, attribute or hook of the user's config runs on it. After
//! a land it prints the command that checks the branch out, for the user
//! to run once they have reviewed it. A land that changes git config
//! (`.gitattributes`, `.gitmodules`, `.lfsconfig`, …) needs
//! `--allow-git-config` (R-T6e).
//!
//! Exit codes: 0 done, 1 a local step failed (git push, a land kept off a
//! branch that is checked out), 2 refused (by the daemon, by a check here,
//! or by the key), 5 the daemon, the key or this build's key support cannot
//! be reached (as `saiife approvals`).

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, BufReader, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ExitCode, Stdio};
use std::time::{Duration, Instant};

use saiife_boxhost::layout::Layout;
use saiife_boxhost::tools::Tools;
use saiife_boxproto::delta::{BlobSink, Limits, Op, Reader, Valid};
use saiife_boxproto::frame::read_frame;
use saiife_boxproto::manifest::{is_oid, EntryKind};
pub use saiife_daemon::box_land::LandInfo;
use saiife_ipc::client::{Client, ClientError};
use saiife_touch::{Touch, TouchError, TouchRequest};
use saiife_wire::source::BoxId;
use serde_json::{json, Map, Value};

use crate::box_cmd::BoxAction;
use crate::box_repo::{self, display_name, one_oid, FALLBACK_IDENT};
use crate::broker::{self, Target};
use crate::text::sanitize;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// `box.land.begin` and `box.diff` may wait for the guest's export (120 s).
const CALL_TIMEOUT: Duration = Duration::from_secs(180);
/// `box.land` may advance a land not taken yet (60 s), export again
/// (120 s) and advance the approved one (60 s) before it answers (M-1).
const LAND_TIMEOUT: Duration = Duration::from_secs(300);
/// The task line of a land commit, in characters.
const TASK_LINE: usize = 72;
/// `box.push.done`'s detail, in characters.
const DETAIL_MAX: usize = 512;
/// The longest worktree dir name taken from the repo's name.
const NAME_MAX: usize = 64;

/// What [`apply`] did. `moved_branch` is false when the branch is checked
/// out in `worktree`: the commit exists (kept by
/// `refs/saiife/box-<id>/land-<n>`), the branch was not moved. Otherwise
/// `worktree` is where saiife suggests checking the branch out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub commit: String,
    pub worktree: PathBuf,
    pub moved_branch: bool,
}

enum Stop {
    /// Exit 2.
    Refused(String),
    /// Exit 5.
    Unavailable(String),
    /// Exit 1.
    Failed(String),
    Touch(TouchError),
    /// These lines, then this exit code.
    Lines(Vec<String>, u8),
}

type Args = Map<String, Value>;

pub fn run(config: Option<&Path>, action: BoxAction) -> ExitCode {
    let r = broker::resolve_here(config)
        .map_err(Stop::Unavailable)
        .and_then(|t| go(&t, action));
    let say = |m: &str, code: u8| {
        for l in m.split('\n') {
            eprintln!("saiife: {}", sanitize(l));
        }
        ExitCode::from(code)
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(Stop::Refused(m)) => say(&m, 2),
        Err(Stop::Unavailable(m)) => say(&m, 5),
        Err(Stop::Failed(m)) => say(&m, 1),
        Err(Stop::Touch(e)) => say(&format!("touch: {e}"), crate::touch_cmd::exit_for(e)),
        Err(Stop::Lines(lines, code)) => say(&lines.join("\n"), code),
    }
}

fn go(t: &Target, action: BoxAction) -> Result<(), Stop> {
    match action {
        BoxAction::Diff { id, json, stat } => diff(t, &box_id(&id)?, json, stat),
        BoxAction::Land {
            id,
            files,
            allow_git_config,
        } => land(t, &box_id(&id)?, files, allow_git_config),
        BoxAction::Apply { id } => {
            let id = box_id(&id)?;
            let tools = tools();
            match apply_waiting(t, &tools, &id)? {
                Waiting::Done(0) => {
                    outln!("nothing to apply for box {}", id.as_str());
                    Ok(())
                }
                Waiting::Done(_) => Ok(()),
                Waiting::Kept(m) => Err(Stop::Failed(m)),
            }
        }
        BoxAction::Push { id, remote } => push(t, &box_id(&id)?, &remote),
        _ => Err(Stop::Failed("not a land command".into())),
    }
}

fn box_id(s: &str) -> Result<BoxId, Stop> {
    BoxId::parse(s).map_err(|_| Stop::Refused(format!("{s:?} is not a box id")))
}

fn tools() -> Tools {
    Tools::system(&Layout::locked().vmm).with_env(&|k| std::env::var_os(k))
}

fn args<const N: usize>(kv: [(&str, Value); N]) -> Args {
    kv.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

// ---------------------------------------------------------------- daemon

fn connect(t: &Target) -> Result<Client, Stop> {
    broker::connect(t, Instant::now() + CONNECT_TIMEOUT)
        .map_err(|e| Stop::Unavailable(broker::unreachable(t, &e)))
}

fn refused(t: &Target, e: ClientError) -> Stop {
    match e {
        ClientError::Refused { code, message } if code == "unavailable" => {
            Stop::Unavailable(message)
        }
        ClientError::Refused { message, .. } => Stop::Refused(message),
        other => Stop::Unavailable(broker::unreachable(t, &other)),
    }
}

fn call(c: &mut Client, t: &Target, op: &str, a: Args) -> Result<Args, Stop> {
    c.call(op, a, Instant::now() + CALL_TIMEOUT)
        .map_err(|e| refused(t, e))
}

/// A call whose answer carries one descriptor (`box.land`, `box.land.fetch`).
fn call_fd(
    c: &mut Client,
    t: &Target,
    op: &str,
    a: Args,
    within: Duration,
) -> Result<(Args, File), Stop> {
    let (a, mut fds) = c
        .call_recv_fds(op, a, 1, Instant::now() + within)
        .map_err(|e| refused(t, e))?;
    match (fds.pop(), fds.is_empty()) {
        (Some(fd), true) => Ok((a, File::from(fd))),
        _ => Err(Stop::Unavailable(format!(
            "the saiife daemon's {op} answer did not carry the land's delta"
        ))),
    }
}

/// The `land` of an answer, checked against the box it is for.
fn land_of(a: &Args, id: &BoxId) -> Result<LandInfo, Stop> {
    let info: LandInfo = serde_json::from_value(a.get("land").cloned().unwrap_or(Value::Null))
        .map_err(|e| {
            Stop::Unavailable(format!(
                "the saiife daemon sent a land this saiife cannot read: {e}"
            ))
        })?;
    check_info(&info, id).map_err(Stop::Unavailable)?;
    Ok(info)
}

fn check_info(info: &LandInfo, id: &BoxId) -> Result<(), String> {
    let bad = |what: &str| Err(format!("the saiife daemon sent a land with {what}"));
    if info.id != *id {
        return bad("another box's id");
    }
    if info.n == 0 {
        return bad("no land number");
    }
    if info.target_ref != format!("saiife/box-{}", id.as_str()) {
        return bad("another target branch");
    }
    if !is_oid(&info.base_commit) {
        return bad("a base commit that is not a commit id");
    }
    let hex = |s: &str| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if !hex(&info.diff_sha256) {
        return bad("a diff hash that is not 64 hex digits");
    }
    Ok(())
}

fn touch_request(b: &Args) -> Result<(String, TouchRequest), Stop> {
    let rid = b
        .get("request_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()))
        .ok_or_else(|| Stop::Unavailable("the saiife daemon sent no request id".into()))?;
    let r: TouchRequest = serde_json::from_value(b.get("touch").cloned().unwrap_or(Value::Null))
        .map_err(|e| {
            Stop::Unavailable(format!(
                "the saiife daemon sent a touch answer this saiife cannot read: {e}"
            ))
        })?;
    Ok((rid.to_string(), r))
}

fn assertion_json(k: &dyn Touch, r: &TouchRequest) -> Result<Value, Stop> {
    let asr = k.request(r).map_err(Stop::Touch)?;
    serde_json::to_value(asr)
        .map_err(|e| Stop::Unavailable(format!("cannot encode the touch: {e}")))
}

// ---------------------------------------------------------------- diff

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn u(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(Value::as_u64).unwrap_or(0)
}

/// The review as terminal lines, every guest-derived string sanitized:
/// the stats, the base, the flags (`! <path>: <why>`), then each file
/// (`stat`) or the unified diff, line by line.
pub(crate) fn review_lines(diff: &Value, review: Option<&Value>, stat: bool) -> Vec<String> {
    let files: &[Value] = diff
        .get("files")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice);
    let (add, rem) = files.iter().fold((0u64, 0u64), |(a, r), f| {
        (a + u(f, "added"), r + u(f, "removed"))
    });
    let mut out = vec![format!(
        "box {}: {} file{} (+{add} -{rem})",
        sanitize(s(diff, "id")),
        files.len(),
        if files.len() == 1 { "" } else { "s" }
    )];
    let base = s(diff, "base_commit");
    if !base.is_empty() {
        let head = review
            .and_then(|r| r.get("base_head"))
            .and_then(Value::as_str)
            .map(|h| format!(" (your HEAD at spawn: {})", sanitize(h)))
            .unwrap_or_default();
        out.push(format!("base {}{head}", sanitize(base)));
    }
    for f in review
        .and_then(|r| r.get("flags"))
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
    {
        out.push(format!(
            "! {}: {}",
            sanitize(s(f, "path")),
            sanitize(s(f, "why"))
        ));
    }
    let git: Vec<String> = review
        .and_then(|r| r.get("git_config"))
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .filter_map(Value::as_str)
        .map(sanitize)
        .collect();
    if !git.is_empty() {
        out.push(format!(
            "this land changes git config ({}); it lands only from the CLI: saiife box land {} --allow-git-config",
            git.join(", "),
            sanitize(s(diff, "id"))
        ));
    }
    if let Some(tr) = diff.get("tests").filter(|t| t.is_object()) {
        out.push(format!(
            "tests: {} passed, {} failed, {} skipped{}",
            u(tr, "passed"),
            u(tr, "failed"),
            u(tr, "skipped"),
            match s(tr, "summary") {
                "" => String::new(),
                x => format!(": {}", sanitize(x)),
            }
        ));
    }
    if stat {
        for f in files {
            let counts = if f.get("binary").and_then(Value::as_bool) == Some(true) {
                "binary".to_string()
            } else {
                format!("+{} -{}", u(f, "added"), u(f, "removed"))
            };
            out.push(format!(
                "  {} {} ({counts})",
                sanitize(s(f, "status")),
                sanitize(s(f, "path"))
            ));
        }
    } else {
        let unified = s(diff, "unified");
        if !unified.is_empty() {
            out.push(String::new());
            out.extend(
                unified
                    .strip_suffix('\n')
                    .unwrap_or(unified)
                    .split('\n')
                    .map(sanitize),
            );
        }
        if diff.get("truncated").and_then(Value::as_bool) == Some(true) {
            out.push(format!(
                "(the diff is cut here; saiife box diff {} --stat lists every file)",
                sanitize(s(diff, "id"))
            ));
        }
    }
    out
}

/// FU1: the warning `box diff` prints before the diff when the box changed
/// files while its in-box guard reported no checks (`guard.skipped`).
pub(crate) fn guard_warning(guard: Option<&Value>) -> Option<String> {
    let skipped = guard
        .and_then(|g| g.get("skipped"))
        .and_then(Value::as_bool);
    (skipped == Some(true)).then(|| {
        format!(
            "warning: guard_skipped: {}",
            saiife_wire::source::GUARD_SKIPPED_WHY
        )
    })
}

fn diff(t: &Target, id: &BoxId, as_json: bool, stat: bool) -> Result<(), Stop> {
    let mut c = connect(t)?;
    let a = call(&mut c, t, "box.diff", args([("box", json!(id.as_str()))]))?;
    let d = a.get("diff").cloned().unwrap_or(Value::Null);
    let r = a.get("review").cloned();
    let g = a.get("guard").cloned();
    if as_json {
        let mut o = json!({"diff": d, "review": r.unwrap_or(Value::Null)});
        if let Some(g) = g {
            o["guard"] = g;
        }
        outln!("{}", crate::box_cmd::ascii_json(&o));
        return Ok(());
    }
    if let Some(w) = guard_warning(g.as_ref()) {
        outln!("{w}");
    }
    for l in review_lines(&d, r.as_ref(), stat) {
        outln!("{l}");
    }
    Ok(())
}

// ---------------------------------------------------------------- land

/// What [`apply_waiting`] ended with.
enum Waiting {
    /// This many lands applied.
    Done(usize),
    /// A land is kept off the branch (it is checked out): the message.
    Kept(String),
}

fn land(t: &Target, id: &BoxId, files: Vec<String>, allow_git_config: bool) -> Result<(), Stop> {
    let i = id.as_str();
    // Errata R-4: no key, no challenge spent; the Workspace can approve.
    let key = crate::touch_cmd::pick().map_err(|m| {
        Stop::Lines(
            vec![
                m,
                format!(
                    "land box {i} from the Workspace instead (Face ID or your passkey), then run: saiife box apply {i}"
                ),
            ],
            5,
        )
    })?;
    let tools = tools();
    // An approved land still waiting for its commit goes first: the new
    // one is built on it.
    if let Waiting::Kept(m) = apply_waiting(t, &tools, id)? {
        return Err(Stop::Failed(m));
    }
    let mut a = args([("box", json!(i))]);
    if !files.is_empty() {
        a.insert("files".into(), json!(files));
    }
    if allow_git_config {
        a.insert("allow_git_config".into(), json!(true));
    }
    let b = call(&mut connect(t)?, t, "box.land.begin", a)?;
    let d = b.get("diff").cloned().unwrap_or(Value::Null);
    for l in review_lines(&d, b.get("review"), true) {
        outln!("{l}");
    }
    let (rid, r) = touch_request(&b)?;
    eprintln!(
        "saiife: touch your key to land box {i} (code {})",
        sanitize(&r.short_code)
    );
    let asr = assertion_json(key.as_ref(), &r)?;
    // A touch may take 120 s: a new connection for the land (D6). From
    // here on the land may be approved whatever the answer: every failure
    // names `saiife box apply` (M-1).
    let landed = (|| {
        let mut c = connect(t)?;
        let (a, delta) = call_fd(
            &mut c,
            t,
            "box.land",
            args([("request_id", json!(rid)), ("assertion", asr)]),
            LAND_TIMEOUT,
        )?;
        drop(c);
        Ok((land_of(&a, id)?, delta))
    })();
    let (info, delta) = landed.map_err(|e| after_touch(i, e))?;
    match apply_one(t, &tools, &info, delta, "landed")? {
        None => Ok(()),
        Some(kept) => Err(Stop::Failed(kept)),
    }
}

/// A `box.land` failure after the touch: the land may be approved (in the
/// Workspace meanwhile, R-T5e, or by this call before its answer was
/// lost), so the message names `saiife box apply`.
fn after_touch(i: &str, e: Stop) -> Stop {
    match e {
        Stop::Refused(m) => Stop::Refused(format!(
            "{m}\nif this land was approved in the Workspace meanwhile, run: saiife box apply {i}"
        )),
        Stop::Unavailable(m) => Stop::Unavailable(format!(
            "{m}\nthe land may have been approved before the answer was lost; run: saiife box apply {i}"
        )),
        other => other,
    }
}

/// Applies every approved land of `id` still waiting for its commit, in
/// order (`box.land.fetch`). Stops at one kept off a checked-out branch.
fn apply_waiting(t: &Target, tools: &Tools, id: &BoxId) -> Result<Waiting, Stop> {
    let i = id.as_str();
    let mut c = connect(t)?;
    let a = call(&mut c, t, "box.land.fetch", args([("box", json!(i))]))?;
    let unreadable = a.get("unreadable").and_then(Value::as_u64).unwrap_or(0);
    if unreadable > 0 {
        eprintln!(
            "saiife: warning: {unreadable} land record(s) of box {i} cannot be read by the daemon"
        );
    }
    let mut ns: Vec<u32> = a
        .get("waiting")
        .and_then(Value::as_array)
        .map(|v| {
            v.iter()
                .filter_map(Value::as_u64)
                .filter_map(|n| u32::try_from(n).ok())
                .collect()
        })
        .unwrap_or_default();
    ns.sort_unstable();
    ns.dedup();
    let mut done = 0;
    for n in ns {
        let (a, delta) = call_fd(
            &mut c,
            t,
            "box.land.fetch",
            args([("box", json!(i)), ("n", json!(n))]),
            CALL_TIMEOUT,
        )?;
        let info = land_of(&a, id)?;
        if info.n != n {
            return Err(Stop::Unavailable(format!(
                "the saiife daemon sent land {} for land {n}",
                info.n
            )));
        }
        if let Some(kept) = apply_one(t, tools, &info, delta, "applied")? {
            return Ok(Waiting::Kept(kept));
        }
        done += 1;
    }
    Ok(Waiting::Done(done))
}

/// [`apply`], then `box.land.applied`. `Some(message)` when the land is
/// kept off the branch.
fn apply_one(
    t: &Target,
    tools: &Tools,
    info: &LandInfo,
    delta: File,
    verb: &str,
) -> Result<Option<String>, Stop> {
    let i = info.id.as_str();
    let n = info.n;
    let Some(repo) = info.repo_dir.as_deref().filter(|r| !r.is_empty()) else {
        return Err(Stop::Refused(format!(
            "box {i} has no repo on record, so land {n} has nowhere to go"
        )));
    };
    let r = apply(tools, Path::new(repo), info, delta).map_err(Stop::Refused)?;
    let wt = r.worktree.display().to_string();
    if !r.moved_branch {
        return Ok(Some(format!(
            "land {n} of box {i} is commit {c}, but saiife/box-{i} is checked out at {wt}, so it was not moved\n\
             to finish: git -C {wt} merge --ff-only {c}\n\
             then run: saiife box apply {i}",
            c = r.commit
        )));
    }
    outln!("{verb} {i} #{n}: {} on saiife/box-{i}", r.commit);
    // R-T6d: checking it out is the user's step, after their review.
    if std::fs::symlink_metadata(&r.worktree).is_ok() {
        outln!(
            "the worktree {} is not updated; to update it: git -C {} merge --ff-only saiife/box-{i}",
            sanitize(&wt),
            sanitize(&wt)
        );
    } else {
        outln!(
            "to check it out: git -C {} worktree add --detach {} saiife/box-{i}",
            sanitize(repo),
            sanitize(&wt)
        );
    }
    let recorded = connect(t).and_then(|mut c| {
        call(
            &mut c,
            t,
            "box.land.applied",
            args([
                ("box", json!(i)),
                ("n", json!(n)),
                ("commit", json!(r.commit)),
            ]),
        )
    });
    match recorded {
        Ok(_) => Ok(None),
        Err(Stop::Refused(m)) | Err(Stop::Unavailable(m)) => Err(Stop::Unavailable(format!(
            "land {n} is on saiife/box-{i} as {}, but the daemon did not record it ({m}); run: saiife box apply {i}",
            r.commit
        ))),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------- push

fn push(t: &Target, id: &BoxId, remote: &str) -> Result<(), Stop> {
    let i = id.as_str();
    saiife_daemon::box_land::check_remote(remote).map_err(|e| Stop::Refused(e.to_string()))?;
    let key = crate::touch_cmd::pick().map_err(Stop::Unavailable)?;
    let tools = tools();
    // The repo here (the current directory) must be the box's: it has the
    // box's base ref. No checkout is needed: the branch tip is pushed.
    let here = std::env::current_dir()
        .map_err(|e| Stop::Failed(format!("cannot read the current directory: {e}")))?;
    let base = format!("refs/saiife/box-{i}/base");
    if rev(&tools, &here, &base).map_err(Stop::Failed)?.is_none() {
        return Err(Stop::Refused(format!(
            "{} is not the repo box {i} started from (it has no {base}); run saiife box push there",
            here.display()
        )));
    }
    let branch = branch_ref(id);
    let commit = rev(&tools, &here, &branch)
        .map_err(Stop::Failed)?
        .ok_or_else(|| {
            Stop::Refused(format!(
                "saiife/box-{i} does not exist yet: saiife box apply {i} first"
            ))
        })?;
    let b = call(
        &mut connect(t)?,
        t,
        "box.push.begin",
        args([
            ("box", json!(i)),
            ("remote", json!(remote)),
            ("commit", json!(commit)),
        ]),
    )?;
    let (rid, r) = touch_request(&b)?;
    eprintln!(
        "saiife: touch your key to push box {i}: {commit} to {} as saiife/box-{i} (code {})",
        sanitize(remote),
        sanitize(&r.short_code)
    );
    let asr = assertion_json(key.as_ref(), &r)?;
    call(
        &mut connect(t)?,
        t,
        "box.push",
        args([("request_id", json!(rid)), ("assertion", asr)]),
    )?;
    // L7: the push itself, as the user, hooks off.
    let refspec = format!("{commit}:refs/heads/saiife/box-{i}");
    let out = box_repo::git_run_env(
        &tools,
        &here,
        None,
        &[
            OsStr::new("push"),
            OsStr::new("--"),
            OsStr::new(remote),
            OsStr::new(&refspec),
        ],
        None,
        &[],
    );
    let (ok, detail) = match &out {
        Ok(o) if o.status.success() => (true, String::new()),
        Ok(o) => (false, last_lines(&o.stderr)),
        Err(e) => (false, e.clone()),
    };
    let done = call(
        &mut connect(t)?,
        t,
        "box.push.done",
        args([
            ("request_id", json!(rid)),
            ("ok", json!(ok)),
            ("detail", json!(detail)),
        ]),
    );
    if !ok {
        return Err(Stop::Failed(format!("git push failed: {detail}")));
    }
    done?;
    outln!(
        "pushed {i}: {commit} to {} as saiife/box-{i}",
        sanitize(remote)
    );
    Ok(())
}

/// The end of git's stderr, at most [`DETAIL_MAX`] chars.
fn last_lines(err: &[u8]) -> String {
    let t = String::from_utf8_lossy(err);
    let t = t.trim();
    let n = t.chars().count();
    if n <= DETAIL_MAX {
        return t.to_string();
    }
    t.chars().skip(n - DETAIL_MAX).collect()
}

// ---------------------------------------------------------------- git

fn git_ok(
    tools: &Tools,
    dir: &Path,
    index: Option<&Path>,
    a: &[&str],
    input: Option<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    box_repo::git_ok_env(tools, dir, index, a, input, &[])
}

/// `git rev-parse --verify -q <r>^{commit}`: the commit, or `None`.
fn rev(tools: &Tools, dir: &Path, r: &str) -> Result<Option<String>, String> {
    let spec = format!("{r}^{{commit}}");
    let o = box_repo::git_run_env(
        tools,
        dir,
        None,
        &[
            OsStr::new("rev-parse"),
            OsStr::new("--verify"),
            OsStr::new("-q"),
            OsStr::new(&spec),
        ],
        None,
        &[],
    )?;
    if !o.status.success() {
        return Ok(None);
    }
    one_oid(o.stdout, "rev-parse").map(Some)
}

fn branch_ref(id: &BoxId) -> String {
    format!("refs/heads/saiife/box-{}", id.as_str())
}

/// One tree entry: mode and object id, by path bytes.
type Tree = BTreeMap<Vec<u8>, (String, String)>;

/// `git ls-tree -r -z --full-tree <treeish>`.
fn tree_of(tools: &Tools, repo: &Path, treeish: &str) -> Result<Tree, String> {
    let out = git_ok(
        tools,
        repo,
        None,
        &["ls-tree", "-r", "-z", "--full-tree", treeish],
        None,
    )?;
    let mut t = Tree::new();
    for rec in out.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let tab = rec
            .iter()
            .position(|b| *b == b'\t')
            .ok_or("git ls-tree: a line with no tab")?;
        let head = std::str::from_utf8(&rec[..tab]).map_err(|_| "git ls-tree: not text")?;
        let mut f = head.split(' ');
        let (Some(mode), Some(_kind), Some(oid)) = (f.next(), f.next(), f.next()) else {
            return Err("git ls-tree: a short line".into());
        };
        t.insert(rec[tab + 1..].to_vec(), (mode.into(), oid.into()));
    }
    Ok(t)
}

/// New content into the object store: one `git hash-object -w --no-filters
/// --stdin` per entry, fed as the reader streams it (no attributes, no
/// filters, no path). Only content whose hash the reader verified is
/// written: an entry that fails is killed before its stdin closes.
struct HashSink<'a> {
    tools: &'a Tools,
    repo: &'a Path,
    child: Option<(Child, ChildStdin)>,
    oids: Vec<String>,
}

impl HashSink<'_> {
    fn abort(&mut self) {
        if let Some((mut c, stdin)) = self.child.take() {
            let _ = c.kill();
            drop(stdin);
            let _ = c.wait();
        }
    }
}

impl Drop for HashSink<'_> {
    fn drop(&mut self) {
        self.abort();
    }
}

impl BlobSink for HashSink<'_> {
    fn begin(&mut self) -> io::Result<()> {
        self.abort();
        let mut c = box_repo::git_cmd(self.tools, self.repo, None);
        c.args(["hash-object", "-w", "--no-filters", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut ch = c.spawn()?;
        let stdin = ch
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("git hash-object has no stdin"))?;
        self.child = Some((ch, stdin));
        Ok(())
    }

    fn write(&mut self, b: &[u8]) -> io::Result<()> {
        match self.child.as_mut() {
            Some((_, stdin)) => stdin.write_all(b),
            None => Err(io::Error::other("content outside an entry")),
        }
    }

    fn finish(&mut self, _sha256: &str) -> io::Result<()> {
        let (ch, stdin) = self
            .child
            .take()
            .ok_or_else(|| io::Error::other("no entry to finish"))?;
        drop(stdin);
        let out = ch.wait_with_output()?;
        if !out.status.success() {
            return Err(io::Error::other(format!(
                "git hash-object failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        let oid = one_oid(out.stdout, "hash-object").map_err(io::Error::other)?;
        self.oids.push(oid);
        Ok(())
    }
}

/// `delta.bin` through `Reader::paths_only` (the path, symlink, size, mode
/// and hash rules; no manifest), its new content written as blobs. The
/// validated entries and, for each that is not a delete, its blob id.
fn read_delta(tools: &Tools, repo: &Path, delta: File) -> Result<(Valid, Vec<String>), String> {
    let mut sink = HashSink {
        tools,
        repo,
        child: None,
        oids: Vec::new(),
    };
    let mut r = BufReader::new(delta);
    let valid = {
        let mut reader = Reader::paths_only(Limits::default(), &mut sink);
        loop {
            let f = read_frame(&mut r)
                .map_err(|e| format!("the land's delta: {e}"))?
                .ok_or("the land's delta ended before its end frame")?;
            if reader.push(f).map_err(|e| e.to_string())? {
                break;
            }
        }
        if read_frame(&mut r)
            .map_err(|e| format!("the land's delta: {e}"))?
            .is_some()
        {
            return Err("the land's delta goes on after its end frame".into());
        }
        reader.finish().map_err(|e| e.to_string())?
    };
    let oids = std::mem::take(&mut sink.oids);
    let want = valid.entries.iter().filter(|h| h.op != Op::Delete).count();
    if oids.len() != want {
        return Err(format!(
            "the land's delta gave {} blobs for {want} entries",
            oids.len()
        ));
    }
    Ok((valid, oids))
}

fn mode_of(kind: &EntryKind, mode: u32) -> &'static str {
    match (kind, mode) {
        (EntryKind::Symlink, _) => "120000",
        (EntryKind::File, 0o755) => "100755",
        (EntryKind::File, _) => "100644",
    }
}

fn kind_matches(mode: &str, kind: &EntryKind) -> bool {
    match kind {
        EntryKind::Symlink => mode == "120000",
        EntryKind::File => mode == "100644" || mode == "100755",
    }
}

/// The parent's tree with the delta applied; refused where the delta's
/// base is not the parent (an add of a path that is there, a change or
/// delete of one that is not, or a path both a file and a directory).
fn expected_tree(parent: &Tree, v: &Valid, oids: &[String]) -> Result<Tree, String> {
    let mut t = parent.clone();
    let mut blobs = oids.iter();
    let off = |p: &str, why: &str| {
        Err(format!(
            "the land does not fit its parent commit at {p:?}: {why}"
        ))
    };
    for h in &v.entries {
        let p = h.path.as_bytes().to_vec();
        let have = t.get(&p).cloned();
        match h.op {
            Op::Delete => match have {
                Some((m, _)) if kind_matches(&m, &h.kind) => {
                    t.remove(&p);
                }
                Some(_) => return off(&h.path, "another kind of entry is there"),
                None => return off(&h.path, "the path to delete is not there"),
            },
            Op::Add | Op::Modify => {
                match (h.op, &have) {
                    (Op::Add, Some(_)) => return off(&h.path, "the path to add is there"),
                    (Op::Modify, None) => return off(&h.path, "the path to change is not there"),
                    (Op::Modify, Some((m, _)))
                        if h.old_kind.as_ref().is_some_and(|k| !kind_matches(m, k)) =>
                    {
                        return off(&h.path, "another kind of entry is there")
                    }
                    _ => {}
                }
                let oid = blobs.next().ok_or("fewer blobs than entries")?;
                t.insert(p, (mode_of(&h.kind, h.mode).into(), oid.clone()));
            }
        }
    }
    for h in v.entries.iter().filter(|h| h.op != Op::Delete) {
        let p = h.path.as_bytes();
        for (i, b) in p.iter().enumerate() {
            if *b == b'/' && t.contains_key(&p[..i]) {
                return off(&h.path, "a parent directory is a file");
            }
        }
        let mut prefix = p.to_vec();
        prefix.push(b'/');
        if t.range(prefix.clone()..)
            .next()
            .is_some_and(|(k, _)| k.starts_with(&prefix))
        {
            return off(&h.path, "it is a directory");
        }
    }
    Ok(t)
}

/// A private dir for the temporary index: `<cache>/box-land/<16 hex>`
/// (0700), removed when dropped.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn abs_env(k: &str) -> Option<PathBuf> {
    std::env::var_os(k)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

fn scratch() -> Result<Scratch, String> {
    let cache = abs_env("XDG_CACHE_HOME")
        .or_else(|| abs_env("HOME").map(|h| h.join(".cache")))
        .ok_or("cannot find your cache dir (HOME is not set)")?;
    let top = cache.join("saiife").join("box-land");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&top)
        .map_err(|e| format!("{}: {e}", top.display()))?;
    let d = top.join(box_repo::random_hex()?);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&d)
        .map_err(|e| format!("{}: {e}", d.display()))?;
    Ok(Scratch(d))
}

/// The first line of the task, without unsafe chars, at most
/// [`TASK_LINE`] chars.
fn task_line(task: &str) -> String {
    let line = task.lines().next().unwrap_or("");
    let clean: String = line
        .chars()
        .filter(|c| !saiife_wire::text::is_unsafe_char(*c) && !c.is_control())
        .collect();
    clean
        .trim()
        .chars()
        .take(TASK_LINE)
        .collect::<String>()
        .trim_end()
        .to_string()
}

/// The land commit's message (Fixed values).
pub(crate) fn message(info: &LandInfo) -> String {
    let i = info.id.as_str();
    let task = task_line(&info.task);
    let task = if task.is_empty() {
        String::new()
    } else {
        format!("{task}\n\n")
    };
    format!(
        "saiife box {i}: land {n}\n\n{task}Saiife-Box: {i}\nSaiife-Land: {n}\nSaiife-Diff-Sha256: {sha}\n",
        n = info.n,
        sha = info.diff_sha256
    )
}

/// Writes the land commit of `delta` on `parent` with plumbing only and
/// returns its id. Nothing in the user's work tree, index or refs changes.
pub fn build_commit(
    tools: &Tools,
    repo: &Path,
    info: &LandInfo,
    delta: File,
    parent: &str,
) -> Result<String, String> {
    if !is_oid(parent) {
        return Err(format!("{parent:?} is not a commit id"));
    }
    let (valid, oids) = read_delta(tools, repo, delta)?;
    if valid.n != info.n {
        return Err(format!(
            "the delta is of export {}, not of land {}",
            valid.n, info.n
        ));
    }
    let base = tree_of(tools, repo, parent)?;
    let want = expected_tree(&base, &valid, &oids)?;

    let dir = scratch()?;
    let index = dir.0.join("index");
    let ix = Some(index.as_path());
    git_ok(tools, repo, ix, &["read-tree", parent], None)?;
    let zero = "0".repeat(parent.len());
    let mut input = Vec::new();
    // Deletes first: a directory that becomes a file (or the reverse) never
    // meets itself in the index.
    for h in valid.entries.iter().filter(|h| h.op == Op::Delete) {
        input.extend_from_slice(format!("0 {zero}\t").as_bytes());
        input.extend_from_slice(h.path.as_bytes());
        input.push(0);
    }
    let changed = valid.entries.iter().filter(|h| h.op != Op::Delete);
    for (h, oid) in changed.zip(&oids) {
        input.extend_from_slice(format!("{} {oid}\t", mode_of(&h.kind, h.mode)).as_bytes());
        input.extend_from_slice(h.path.as_bytes());
        input.push(0);
    }
    if !input.is_empty() {
        git_ok(
            tools,
            repo,
            ix,
            &["update-index", "-z", "--index-info"],
            Some(input),
        )?;
    }
    let tree = one_oid(
        git_ok(tools, repo, ix, &["write-tree"], None)?,
        "write-tree",
    )?;
    drop(dir);
    if tree_of(tools, repo, &tree)? != want {
        return Err("git wrote another tree than the land's".into());
    }
    let has_ident = box_repo::git_run_env(
        tools,
        repo,
        None,
        &[OsStr::new("var"), OsStr::new("GIT_COMMITTER_IDENT")],
        None,
        &[],
    )?
    .status
    .success();
    let env: &[(&str, &str)] = if has_ident { &[] } else { &FALLBACK_IDENT };
    one_oid(
        box_repo::git_ok_env(
            tools,
            repo,
            None,
            &["commit-tree", &tree, "-p", parent, "-F", "-"],
            Some(message(info).into_bytes()),
            env,
        )?,
        "commit-tree",
    )
}

/// `<data>/saiife/worktrees/<repo>-<id>`; `<data>` is `$XDG_DATA_HOME` (an
/// absolute one), else `$HOME/.local/share`. `repo` is the repo's display
/// name, kept to `[A-Za-z0-9._-]`.
fn worktree_dir(repo: &str, id: &BoxId) -> Result<PathBuf, String> {
    let data = abs_env("XDG_DATA_HOME")
        .or_else(|| abs_env("HOME").map(|h| h.join(".local").join("share")))
        .ok_or("cannot find your data dir (HOME is not set)")?;
    let mut name: String = repo
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .take(NAME_MAX)
        .collect();
    while name.starts_with('.') || name.starts_with('-') {
        name.remove(0);
    }
    if name.is_empty() {
        name = "repo".into();
    }
    Ok(data
        .join("saiife")
        .join("worktrees")
        .join(format!("{name}-{}", id.as_str())))
}

/// The land trailers of a commit's message: `(box, land, diff sha)`.
fn trailers(raw: &[u8]) -> Option<(String, u32, String)> {
    let text = String::from_utf8_lossy(raw);
    let msg = text.split_once("\n\n")?.1;
    let last = msg.trim_end().rsplit("\n\n").next()?;
    let (mut b, mut n, mut sha) = (None, None, None);
    for l in last.lines() {
        if let Some(v) = l.strip_prefix("Saiife-Box: ") {
            b = Some(v.to_string());
        } else if let Some(v) = l.strip_prefix("Saiife-Land: ") {
            n = v.parse().ok();
        } else if let Some(v) = l.strip_prefix("Saiife-Diff-Sha256: ") {
            sha = Some(v.to_string());
        }
    }
    Some((b?, n?, sha?))
}

/// A commit's parents (its header's `parent` lines).
fn parents(raw: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(raw);
    let head = text.split_once("\n\n").map_or(&*text, |(h, _)| h);
    head.lines()
        .filter_map(|l| l.strip_prefix("parent "))
        .map(str::to_string)
        .collect()
}

fn cat_commit(tools: &Tools, repo: &Path, c: &str) -> Result<Vec<u8>, String> {
    git_ok(tools, repo, None, &["cat-file", "commit", c], None)
}

/// The base ref, recreated from the land's base commit when it is missing
/// and git still has the commit (p37 R14).
fn base_of(tools: &Tools, repo: &Path, info: &LandInfo) -> Result<String, String> {
    let i = info.id.as_str();
    let r = format!("refs/saiife/box-{i}/base");
    match rev(tools, repo, &r)? {
        Some(c) if c == info.base_commit => Ok(c),
        Some(c) => Err(format!(
            "{r} in {} points at {c}, not at the box's base commit {}: is this the repo box {i} started from?",
            repo.display(),
            info.base_commit
        )),
        None => {
            let spec = format!("{}^{{commit}}", info.base_commit);
            let there = box_repo::git_run_env(
                tools,
                repo,
                None,
                &[OsStr::new("cat-file"), OsStr::new("-e"), OsStr::new(&spec)],
                None,
                &[],
            )?
            .status
            .success();
            if !there {
                return Err(format!(
                    "the box's base commit {} is no longer in {} (its base ref was deleted and git gc removed it); this land cannot be applied",
                    info.base_commit,
                    repo.display()
                ));
            }
            box_repo::set_base_ref(tools, repo, &info.id, &info.base_commit)?;
            Ok(info.base_commit.clone())
        }
    }
}

/// One entry of `git worktree list --porcelain` (not `-z`: git 2.36 and
/// later only; a path with a newline is not one of saiife's worktrees).
struct Worktree {
    path: PathBuf,
    branch: Option<String>,
}

fn worktrees(tools: &Tools, repo: &Path) -> Result<Vec<Worktree>, String> {
    let out = git_ok(
        tools,
        repo,
        None,
        &["worktree", "list", "--porcelain"],
        None,
    )?;
    let mut list = Vec::new();
    let mut cur: Option<Worktree> = None;
    for f in out.split(|b| *b == b'\n') {
        if f.is_empty() {
            list.extend(cur.take());
            continue;
        }
        if let Some(p) = f.strip_prefix(b"worktree ") {
            list.extend(cur.take());
            cur = Some(Worktree {
                path: PathBuf::from(OsStr::from_bytes(p)),
                branch: None,
            });
        } else if let Some(w) = cur.as_mut() {
            if let Some(b) = f.strip_prefix(b"branch ") {
                w.branch = Some(String::from_utf8_lossy(b).into_owned());
            }
        }
    }
    list.extend(cur);
    Ok(list)
}

/// Writes land `info` (its `delta.bin`) as a commit on `saiife/box-<id>`
/// of `repo` (the box's `repo_dir`). Only refs move: nothing of the box is
/// checked out or merged, so no checkout filter, attribute or hook of the
/// user's config ever runs on box content (R-T6d).
///
/// - The base ref must name the land's base commit (recreated when
///   missing, refused when git gc removed the commit).
/// - The parent is the branch's tip, which must be the base or a land
///   commit of this box older than `n`; any other tip is a branch moved by
///   hand and is refused. A tip that already is land `n` (same diff hash)
///   is the land, applied before: nothing is written.
/// - The branch moves with `update-ref <branch> <new> <old-or-empty>`
///   (compare and swap). A branch checked out in some worktree is not
///   moved under it: the commit is kept (`refs/saiife/box-<id>/land-<n>`),
///   `moved_branch` is false and `worktree` names that checkout.
/// - Otherwise `worktree` is where saiife suggests checking it out:
///   `$XDG_DATA_HOME/saiife/worktrees/<repo>-<id>`.
pub fn apply(tools: &Tools, repo: &Path, info: &LandInfo, delta: File) -> Result<Applied, String> {
    let i = info.id.as_str();
    let n = info.n;
    let branch = branch_ref(&info.id);
    if !repo.is_absolute() {
        return Err(format!(
            "the box's repo {} is not an absolute path",
            repo.display()
        ));
    }
    git_ok(tools, repo, None, &["rev-parse", "--git-dir"], None)
        .map_err(|e| format!("{} is not a git repo: {e}", repo.display()))?;
    let base = base_of(tools, repo, info)?;
    let wt = worktree_dir(&display_name(repo), &info.id)?;

    let tip = rev(tools, repo, &branch)?;
    let mut new = None;
    let parent = match &tip {
        None => base.clone(),
        Some(t) if *t == base => t.clone(),
        Some(t) => {
            let raw = cat_commit(tools, repo, t)?;
            let moved = || {
                format!(
                    "saiife/box-{i} has moved: its tip {t} is not a land commit of box {i}; point it back at the last land commit (git branch -f saiife/box-{i} <commit>), then run: saiife box apply {i}"
                )
            };
            let Some((b, m, sha)) = trailers(&raw) else {
                return Err(moved());
            };
            let from_base = box_repo::git_run_env(
                tools,
                repo,
                None,
                &[
                    OsStr::new("merge-base"),
                    OsStr::new("--is-ancestor"),
                    OsStr::new(&base),
                    OsStr::new(t),
                ],
                None,
                &[],
            )?
            .status
            .success();
            if b != i || !from_base {
                return Err(moved());
            }
            if m == n {
                if sha != info.diff_sha256 {
                    return Err(format!(
                        "saiife/box-{i} already has a land {n} with another diff hash ({sha}); this land cannot be applied"
                    ));
                }
                // Applied before (the record of it was lost).
                new = Some(t.clone());
            } else if m > n {
                return Err(format!(
                    "saiife/box-{i} already has land {m}, which is newer than land {n}"
                ));
            }
            t.clone()
        }
    };

    let keep = format!("refs/saiife/box-{i}/land-{n}");
    let new = match new {
        Some(c) => c,
        None => {
            // A land kept off a checked-out branch before is written once.
            let kept = match rev(tools, repo, &keep)? {
                Some(k) => {
                    let raw = cat_commit(tools, repo, &k)?;
                    let same = parents(&raw) == [parent.clone()]
                        && trailers(&raw) == Some((i.to_string(), n, info.diff_sha256.clone()));
                    same.then_some(k)
                }
                None => None,
            };
            match kept {
                Some(k) => k,
                None => build_commit(tools, repo, info, delta, &parent)?,
            }
        }
    };
    if tip.as_deref() == Some(new.as_str()) {
        return Ok(Applied {
            commit: new,
            worktree: wt,
            moved_branch: true,
        });
    }
    // Moving a checked-out branch would leave that checkout's files behind
    // its HEAD; its owner fast-forwards it instead.
    if let Some(w) = worktrees(tools, repo)?
        .into_iter()
        .find(|w| w.branch.as_deref() == Some(branch.as_str()))
    {
        git_ok(tools, repo, None, &["update-ref", &keep, &new], None)?;
        return Ok(Applied {
            commit: new,
            worktree: w.path,
            moved_branch: false,
        });
    }
    git_ok(
        tools,
        repo,
        None,
        &["update-ref", &branch, &new, tip.as_deref().unwrap_or("")],
        None,
    )
    .map_err(|e| format!("saiife/box-{i} moved while the land was written: {e}"))?;
    Ok(Applied {
        commit: new,
        worktree: wt,
        moved_branch: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(task: &str) -> LandInfo {
        LandInfo {
            id: BoxId::parse("b1").unwrap(),
            n: 3,
            target_ref: "saiife/box-b1".into(),
            base_commit: "a".repeat(40),
            diff_sha256: "b".repeat(64),
            task: task.into(),
            repo_dir: Some("/r".into()),
        }
    }

    /// M-1: `box.land` waits past the daemon's worst case, and every
    /// failure after the touch names `saiife box apply`.
    #[test]
    fn land_failures_after_the_touch_name_apply() {
        assert!(
            LAND_TIMEOUT
                > saiife_boxhost::review::EXPORT_TIMEOUT
                    + 2 * saiife_daemon::box_land::ADVANCE_TIMEOUT
        );
        let hint = "run: saiife box apply b1";
        for e in [
            Stop::Unavailable("the saiife daemon did not answer in time".into()),
            Stop::Refused("refused (touch_mismatch)".into()),
        ] {
            match after_touch("b1", e) {
                Stop::Unavailable(m) | Stop::Refused(m) => assert!(m.contains(hint), "{m}"),
                _ => panic!("another kind"),
            }
        }
    }

    #[test]
    fn message_is_the_fixed_shape() {
        let m = message(&info("fix the \u{202e}parser\nsecond line"));
        assert_eq!(
            m,
            format!(
                "saiife box b1: land 3\n\nfix the parser\n\nSaiife-Box: b1\nSaiife-Land: 3\nSaiife-Diff-Sha256: {}\n",
                "b".repeat(64)
            )
        );
        let long = message(&info(&"x".repeat(100)));
        assert!(
            long.contains(&format!("\n\n{}\n\n", "x".repeat(72))),
            "{long}"
        );
        let empty = message(&info("\u{7}"));
        assert!(
            empty.starts_with("saiife box b1: land 3\n\nSaiife-Box: b1\n"),
            "{empty}"
        );
    }

    #[test]
    fn trailers_read_the_last_paragraph_only() {
        let raw = format!("tree x\nparent y\n\n{}", message(&info("Saiife-Land: 99")));
        assert_eq!(
            trailers(raw.as_bytes()),
            Some(("b1".into(), 3, "b".repeat(64)))
        );
        assert_eq!(parents(raw.as_bytes()), vec!["y".to_string()]);
        assert_eq!(trailers(b"tree x\n\nhello\n"), None);
    }

    #[test]
    fn info_is_checked() {
        let id = BoxId::parse("b1").unwrap();
        assert!(check_info(&info(""), &id).is_ok());
        let mut i = info("");
        i.target_ref = "main".into();
        assert!(check_info(&i, &id).is_err());
        let mut i = info("");
        i.diff_sha256 = "B".repeat(64);
        assert!(check_info(&i, &id).is_err());
        assert!(check_info(&info(""), &BoxId::parse("b2").unwrap()).is_err());
    }

    #[test]
    fn guard_warning_only_when_skipped() {
        let w = guard_warning(Some(&json!({"skipped": true, "checks": 0, "turns": 2}))).unwrap();
        assert_eq!(
            w,
            format!(
                "warning: guard_skipped: {}",
                saiife_wire::source::GUARD_SKIPPED_WHY
            )
        );
        assert!(
            w.starts_with("warning: guard_skipped: the box changed files"),
            "{w}"
        );
        assert!(w.contains("a signal only"), "{w}");
        assert_eq!(
            guard_warning(Some(&json!({"skipped": false, "checks": 3, "turns": 2}))),
            None
        );
        assert_eq!(guard_warning(Some(&json!({"skipped": "yes"}))), None);
        assert_eq!(guard_warning(None), None);
    }

    #[test]
    fn review_lines_sanitize_every_path() {
        let d = json!({"id": "b1", "base_commit": "c", "unified": "+a\u{202e}\n-b\n",
            "files": [{"path": "x\u{202e}", "status": "added", "added": 1, "removed": 0, "binary": false}],
            "truncated": false, "tests": null});
        let r = json!({"flags": [{"path": "y\u{1b}", "why": "new symlink"}], "base_head": "h"});
        for stat in [true, false] {
            let l = review_lines(&d, Some(&r), stat);
            assert!(
                l.iter()
                    .all(|l| !l.contains('\u{202e}') && !l.contains('\u{1b}')),
                "{l:?}"
            );
            assert_eq!(l[0], "box b1: 1 file (+1 -0)");
            assert!(l.iter().any(|l| l.starts_with("! y")), "{l:?}");
        }
    }
}
