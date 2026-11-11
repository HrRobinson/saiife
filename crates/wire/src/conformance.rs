//! The `BoxSource` conformance kit. Plan 34 (the real box manager) runs
//! `check` against its implementation; the fake passes it in this crate's
//! tests. Each rule that fails returns `Err` with a message that starts with
//! the rule's name.
//!
//! `terminal(id, after)` contract the kit relies on: frames with `seq > after`
//! (all when `None`), `next` = the highest `seq` returned or
//! `after.unwrap_or(0)` when none, `ended` = the box is Done, Landed or
//! Discarded.

use crate::source::*;
use saiife_touch::{TouchClass, TouchEvidence};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// What `check` needs: a source in a known state. The source must be
/// quiescent: no other actor between calls and a stable queue (scheduler held
/// or all slots busy), so the kit does not fail spuriously under real timing.
pub struct Fixture<'a> {
    pub source: &'a dyn BoxSource,
    /// A Running box.
    pub running: BoxId,
    /// A Done box.
    pub done: BoxId,
    /// Every queued box of the source, at least two.
    pub queued: Vec<BoxId>,
    /// A template name that `templates()` lists.
    pub template: String,
}

// The overview order key is deliberately duplicated here (not shared with
// fake.rs): an independent oracle for the order rule.
fn rank(s: BoxState) -> u8 {
    match s {
        BoxState::Running => 0,
        BoxState::Paused => 1,
        BoxState::Done => 2,
        BoxState::Queued => 3,
        BoxState::Starting => 4,
        _ => 5,
    }
}

fn is_rule<T>(r: Result<T, BoxError>, want: &str) -> bool {
    matches!(r, Err(e) if e.rule() == want)
}

fn fail<T>(rule: &str, why: impl std::fmt::Display) -> Result<T, String> {
    Err(format!("{rule}: {why}"))
}

/// Run every rule. It mutates the source (stop, reorder, spawn attempts), so
/// give it a fresh fixture; `fx.queued` must list every queued box (>= 2).
/// Non-mutating rules run first, then the mutating ones.
pub fn check(fx: &Fixture) -> Result<(), String> {
    let src = fx.source;
    if fx.queued.len() < 2 {
        return fail("fixture", "needs at least two queued boxes");
    }

    let list = src.list();
    let state_of = |i: &BoxId| list.iter().find(|b| &b.id == i).map(|b| b.state);
    if state_of(&fx.running) != Some(BoxState::Running) {
        return fail("fixture", "running is not a Running box");
    }
    if state_of(&fx.done) != Some(BoxState::Done) {
        return fail("fixture", "done is not a Done box");
    }
    let mut q_fx: Vec<&BoxId> = fx.queued.iter().collect();
    let mut q_src: Vec<&BoxId> = list
        .iter()
        .filter(|b| b.state == BoxState::Queued)
        .map(|b| &b.id)
        .collect();
    q_fx.sort();
    q_src.sort();
    if q_fx != q_src {
        return fail("fixture", "queued is not exactly the set of Queued boxes");
    }

    // --- non-mutating rules ---
    let overview = src.overview();
    if overview.slots_free > overview.slots_total {
        return fail("slots", "slots_free exceeds slots_total");
    }
    let mut positions: Vec<u32> = Vec::new();
    for b in &list {
        match (b.state, b.queue_pos) {
            (BoxState::Queued, Some(p)) => positions.push(p),
            (BoxState::Queued, None) => return fail("queue_pos", "queued box without one"),
            (_, Some(_)) => return fail("queue_pos", "non-queued box has one"),
            _ => {}
        }
    }
    positions.sort();
    if positions != (1..=positions.len() as u32).collect::<Vec<_>>() {
        return fail(
            "queue_pos",
            format!("positions are not 1..=n: {positions:?}"),
        );
    }
    let mut a: Vec<&str> = overview.boxes.iter().map(|b| b.id.as_str()).collect();
    let mut b: Vec<&str> = list.iter().map(|b| b.id.as_str()).collect();
    a.sort();
    b.sort();
    if a != b {
        return fail("overview ids equal list ids", format!("{a:?} vs {b:?}"));
    }
    for i in &list {
        if BoxId::parse(i.id.as_str()).is_err() {
            return fail("ids parse", i.id.as_str());
        }
    }
    let key = |x: &BoxInfo| {
        (
            rank(x.state),
            if x.state == BoxState::Queued {
                x.queue_pos.unwrap_or(u32::MAX)
            } else {
                0
            },
            x.id.clone(),
        )
    };
    for w in overview.boxes.windows(2) {
        if key(&w[0]) > key(&w[1]) {
            return fail(
                "overview order",
                format!("{} before {}", w[0].id.as_str(), w[1].id.as_str()),
            );
        }
    }
    let templates = src.templates();
    let names: HashSet<&str> = templates.iter().map(|t| t.name.as_str()).collect();
    if names.len() != templates.len() {
        return fail("templates unique", "duplicate template name");
    }
    if !names.contains(fx.template.as_str()) {
        return fail("fixture", "template is not listed by templates()");
    }
    let mut seen = HashSet::new();
    for p in src.pending_actions() {
        if p.record.class == TouchClass::Land {
            if p.box_id.is_none() {
                return fail(
                    "land binding",
                    format!("pending land {} names no box", p.request_id),
                );
            }
            if let Some(bid) = &p.box_id {
                let d = match src.diff(bid) {
                    Ok(d) => d,
                    Err(e) => return fail("land binding", format!("diff failed: {e}")),
                };
                let f = |k: &str| p.record.fields.get(k).map(String::as_str);
                if f("diff_sha256") != Some(d.diff_sha256.as_str())
                    || f("base_commit") != Some(d.base_commit.as_str())
                {
                    return fail(
                        "land binding",
                        format!(
                            "record of request {} does not bind the diff shown",
                            p.request_id
                        ),
                    );
                }
            }
        }
        if p.expires_at <= p.created_at {
            return fail("pending expiry", format!("request {}", p.request_id));
        }
        if p.request_id != p.record.request_id
            || p.class != p.record.class
            || p.expires_at != p.record.expires_at
            || p.summary != p.record.summary
        {
            return fail(
                "pending mirrors record",
                format!("request {}", p.request_id),
            );
        }
        if !seen.insert(p.request_id) {
            return fail("pending request ids unique", p.request_id);
        }
    }
    let absent = (1..)
        .map(|n| format!("x-absent-{n}"))
        .find(|s| !list.iter().any(|b| b.id.as_str() == s))
        .and_then(|s| BoxId::parse(&s).ok())
        .ok_or("fixture: no absent id")?;
    if !is_rule(src.diff(&absent), "not_found") {
        return fail("diff of unknown id is not_found", absent.as_str());
    }
    if !is_rule(src.terminal(&absent, None), "not_found") {
        return fail("terminal of unknown id is not_found", absent.as_str());
    }
    if !is_rule(src.stop(&absent), "not_found") {
        return fail("stop of unknown id is not_found", absent.as_str());
    }
    let mut absent_req = 1u64;
    let live: HashSet<u64> = src.pending_actions().iter().map(|p| p.request_id).collect();
    while live.contains(&absent_req) {
        absent_req += 1;
    }
    if !is_rule(
        src.complete(absent_req, Decision::Reject, None),
        "not_found",
    ) {
        return fail("complete of unknown request is not_found", absent_req);
    }
    match src.diff(&fx.done) {
        Ok(d)
            if d.unified.len() <= MAX_DIFF_BYTES
                && d.diff_sha256.len() == 64
                && d.diff_sha256
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) => {}
        Ok(_) => return fail("diff is capped and hashed", fx.done.as_str()),
        Err(e) => return fail("diff of done box", e),
    }
    if let Ok(d) = src.diff(&fx.done) {
        if !d.truncated && d.diff_sha256 != crate::b64::hex(&Sha256::digest(d.unified.as_bytes())) {
            return fail(
                "diff is capped and hashed",
                "diff_sha256 is not sha256(unified)",
            );
        }
    }
    match src.terminal(&fx.done, None) {
        Ok(t) if t.ended => {}
        other => return fail("terminal of a done box has ended", format!("{other:?}")),
    }

    // --- mutating rules ---
    let before = src.list().len();
    let bad = SpawnReq {
        template: (1..)
            .map(|n| format!("absent-template-{n}"))
            .find(|t| !names.contains(t.as_str()))
            .ok_or("fixture: no absent template")?,
        repo: "r".into(),
        task: "t".into(),
        start: Start::Queue,
    };
    if !is_rule(src.spawn(&bad), "invalid") {
        return fail("spawn with unknown template is invalid", &bad.template);
    }
    if src.list().len() != before {
        return fail(
            "spawn with unknown template creates no box",
            "box count changed",
        );
    }
    if !is_rule(src.stop(&fx.queued[0]), "wrong_state") {
        return fail("stop of a queued box is wrong_state", fx.queued[0].as_str());
    }
    if let Some(p) = src.pending_actions().first() {
        let ev = TouchEvidence {
            credential_id: "c".into(),
            kind: "webauthn",
            user_verified: true,
            sign_count: 1,
            challenge_hex: "0".repeat(64),
            label: "k".into(),
            via: "web",
            flags: 5,
            auth_data: vec![0; 37],
            client_data: None,
            client_data_hash: [0; 32],
            signature: vec![1],
            preimage_hex: String::new(),
            action: "x".into(),
        };
        if !is_rule(
            src.complete(p.request_id, Decision::Reject, Some(ev)),
            "invalid",
        ) {
            return fail("complete reject with evidence is invalid", p.request_id);
        }
        if !is_rule(
            src.complete(p.request_id, Decision::Approve, None),
            "invalid",
        ) {
            return fail("complete approve without evidence is invalid", p.request_id);
        }
        if !src
            .pending_actions()
            .iter()
            .any(|q| q.request_id == p.request_id)
        {
            return fail("invalid complete leaves the pending action", p.request_id);
        }
    }
    if let Err(e) = src.steer(&fx.running, "ok") {
        return fail("steer of a running box is ok", e);
    }
    if !is_rule(src.steer(&fx.running, "a\x1bb"), "invalid") {
        return fail("steer with a control byte is invalid", "ESC accepted");
    }
    if !is_rule(src.revise(&fx.running, "again"), "wrong_state") {
        return fail(
            "revise of a running box is wrong_state",
            fx.running.as_str(),
        );
    }
    if !is_rule(src.reorder(&fx.queued[..1]), "invalid") {
        return fail("reorder of a partial set is invalid", "subset accepted");
    }
    let mut extra = fx.queued.clone();
    extra.push(absent.clone());
    if !is_rule(src.reorder(&extra), "invalid") {
        return fail("reorder with a foreign id is invalid", "superset accepted");
    }
    let reversed: Vec<BoxId> = fx.queued.iter().rev().cloned().collect();
    if let Err(e) = src.reorder(&reversed) {
        return fail("reorder of the queued set", e);
    }
    let mut by_pos: Vec<BoxInfo> = src
        .list()
        .into_iter()
        .filter(|b| b.state == BoxState::Queued)
        .collect();
    by_pos.sort_by_key(|b| b.queue_pos.unwrap_or(u32::MAX));
    let got: Vec<&BoxId> = by_pos.iter().map(|b| &b.id).collect();
    if got != reversed.iter().collect::<Vec<_>>() {
        return fail("reorder shows in queue_pos", format!("{got:?}"));
    }
    for n in 1..=2 {
        if let Err(e) = src.stop(&fx.running) {
            return fail("stop is idempotent", format!("stop call {n} failed: {e}"));
        }
        let st = src
            .list()
            .into_iter()
            .find(|b| b.id == fx.running)
            .map(|b| b.state);
        if st != Some(BoxState::Done) {
            return fail(
                "stop is idempotent",
                format!("after stop call {n} the box is {st:?}, not Done"),
            );
        }
    }
    if let Err(e) = src.revise(&fx.done, "rework") {
        return fail("revise of a done box", e);
    }
    if src
        .pending_actions()
        .iter()
        .any(|p| p.record.class == TouchClass::Land && p.box_id.as_ref() == Some(&fx.done))
    {
        return fail(
            "revise drops the pending land",
            "a pending land still names the revised box",
        );
    }
    Ok(())
}
