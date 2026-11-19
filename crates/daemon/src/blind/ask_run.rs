//! The run of an ask (plan 48 Task 2; R48-3, R48-4, R48-2b, R-C5, R-C12;
//! spec §2.3.4 to §2.3.6, §5.2, §6.5): a child module of [`super`] (the
//! ask state machine), split off for size.
//!
//! After the preview the user says Run or Stop (or `--yes` ran it at
//! once). Stop ends the ask (`blind_preview {outcome: "stopped"}`). Run
//! checks the role again (R-C12), records the acceptance, keeps the turn
//! in the session (plan 44 R44-5), runs the validated method in the
//! calculator child on the ask's held build ([`calc::run`] strips the
//! parameter displays), fills the template with the user's own words for
//! each entity ([`answer_params`], R48-2b) and puts the answer through the
//! strict checker ([`checker::check`], which runs the parameter coverage
//! again, ruling F-f). Once the preview was shown nothing is planned
//! again (R48-2): every failure from here ends the ask with a refusal that
//! carries the method line, and writes `blind_check_refused` with its
//! code (never the reason: it can name the user's words).
//!
//! `blind_run` holds the method's hash (or the approved id), the snapshot
//! hash, the calculator's label and confinement, and the answer's sha256;
//! the answer text is never logged.

use super::*;
use crate::blind::calc::{self, Outcome};
use saiife_shield::answer::{cap_note, footer, method_line};
use saiife_shield::calc::{Caps, ResultSet};
use saiife_shield::calc_proto::{CalcJob, CALC_JOB_VERSION};
use saiife_shield::checker;
use saiife_shield::envelope::turn_for;
use saiife_shield::sql::IDENTIFIER_OUTPUT_REASON;
use saiife_shield::template::{
    answer_params, empty_for_key_reason, empty_result_reason, fill, Filled,
};
use saiife_system::sandbox::CALC_LABEL;

/// `{"run": false}` (R48-3).
pub const STOPPED: &str = "stopped before the method ran";
/// The acceptance could not be recorded: nothing ran.
pub const ACCEPT_UNRECORDED: &str = "the run could not be recorded, so the method did not run";
/// The stop could not be recorded (the method did not run either).
pub const STOP_UNRECORDED: &str = "the stop could not be recorded; the method did not run";
/// `blind_run` could not be written: the answer is not shown.
pub const RUN_UNRECORDED: &str = "the run could not be recorded, so its answer is not shown";
/// The result does not fill the template (a NULL or a non-number cell).
pub const FILL_FAILED: &str = "the method's result does not fit the answer template";
/// A self-check of the planner's failed.
pub const SELF_CHECK_FAILED: &str = "a self-check of the method failed";
/// The calculator's time or step cap.
pub const TIME_CAP_TEXT: &str = "the method ran past its time limit";
/// The calculator could not confine itself: nothing ran.
pub const SANDBOX_TEXT: &str = "the calculator could not confine itself, so the method did not run";

/// Previewing, then Run (`go`) or Stop. `accepted`: record the user's
/// Run as `blind_preview {outcome: "accepted"}` (`--yes` recorded `auto`
/// with the preview). An answer leaves the ask `Answered`; anything else
/// leaves it `Done`.
pub(super) async fn run_or_stop(
    ctx: &Arc<Ctx>,
    id: &str,
    mut st: AskState,
    go: bool,
    accepted: bool,
) -> (AskState, Result<Step, Refusal>) {
    let AskPhase::Previewing {
        draft,
        validated,
        reply,
        preview,
        approved,
    } = std::mem::replace(&mut st.phase, AskPhase::Done)
    else {
        return (st, Err(misfit()));
    };
    if !go {
        let r = stop(ctx, id, &st, &draft, &preview, approved.is_some()).await;
        return (st, r);
    }
    // R-C12: the role and the dataset, again, right before the run.
    if let Err(r) = still_allowed(ctx, id, &st).await {
        return (st, Err(r));
    }
    if accepted {
        let r = preview_record(id, &preview, "accepted");
        if let Err(e) = record(ctx, &st, r, ACCEPT_UNRECORDED).await {
            return (st, Err(e));
        }
    }
    let r = execute(
        ctx,
        id,
        &st,
        &draft,
        &validated,
        &reply,
        &preview,
        approved.as_deref(),
    )
    .await;
    if matches!(r, Ok(Step::Answer { .. })) {
        st.phase = AskPhase::Answered {
            draft,
            reply,
            preview,
        };
    }
    (st, r)
}

/// `blind_preview` of `outcome` for `p`.
pub(super) fn preview_record(id: &str, p: &Preview, outcome: &'static str) -> BlindRecord {
    BlindRecord::Preview {
        ask: id.to_string(),
        sha256: p.sha256.clone(),
        outcome,
        fragments: u32::try_from(p.fragments).unwrap_or(u32::MAX),
    }
}

async fn stop(
    ctx: &Ctx,
    id: &str,
    st: &AskState,
    d: &Draft,
    p: &Preview,
    reused: bool,
) -> Result<Step, Refusal> {
    record(ctx, st, preview_record(id, p, "stopped"), STOP_UNRECORDED).await?;
    // A reused method sent nothing; otherwise the planner was asked.
    let head = if reused {
        head_nothing_sent(d.lang)
    } else {
        head_no_answer(d.lang)
    };
    Ok(Step::refused(code::STOPPED, head, STOPPED))
}

/// The session keeps this ask's turn (R44-5): later asks send it as
/// context, with the same stand-ins.
async fn push_turn(ctx: &Arc<Ctx>, st: &AskState, d: &Draft) -> Result<(), Refusal> {
    let keys = load_keys(ctx, &st.dataset).await?;
    let schema = st.snapshot.schema();
    let mut ss = lock(&ctx.blind.sessions);
    let s = ss
        .get_or_new(
            st.uid,
            &st.dataset,
            &keys,
            unix_now(),
            st.opts.session,
            false,
        )
        .map_err(|e| shield_err(&e))?;
    let t = turn_for(d, s, schema, st.released.clone());
    s.push_turn(t);
    Ok(())
}

/// The run itself, from the job to the answer step.
#[allow(clippy::too_many_arguments)]
async fn execute(
    ctx: &Arc<Ctx>,
    id: &str,
    st: &AskState,
    d: &Draft,
    v: &Validated,
    reply: &PlanReply,
    preview: &Preview,
    approved: Option<&str>,
) -> Result<Step, Refusal> {
    let lang = d.lang;
    let line = method_line(&preview.text, lang);
    push_turn(ctx, st, d).await?;
    let snap = &st.snapshot;
    let schema = snap.schema();
    let job = CalcJob {
        v: CALC_JOB_VERSION,
        // `calc::run` sets both from the held build.
        snapshot: std::path::PathBuf::new(),
        snapshot_sha256: String::new(),
        schema: schema.clone(),
        public: snap.manifest.public.clone(),
        method: reply.method.clone(),
        checks: reply.checks.clone(),
        // `calc::run` strips the displays: the calculator needs no names.
        params: d.params.clone(),
        caps: Caps {
            list_cap: st.opts.list_cap,
            ..Caps::default()
        },
    };
    let answer = match calc::run(ctx, &**snap, job).await {
        Ok(a) => a,
        Err(text) => {
            refused_record(ctx, id, st, "calculator_unavailable").await;
            return Err(unavailable(text));
        }
    };
    let (result, conf) = match calc::outcome(&answer) {
        Outcome::Ran {
            result,
            confinement,
        } => (result, confinement),
        Outcome::SandboxUnavailable => {
            refused_record(ctx, id, st, "sandbox_unavailable").await;
            return Err(unavailable(SANDBOX_TEXT));
        }
        o => {
            let (c, reason) = calc_refusal(&o, d, schema);
            return Ok(after_run_refusal(ctx, id, st, c, reason, line, lang).await);
        }
    };
    let checked = check_answer(st, d, v, reply, result);
    let r = BlindRecord::Run {
        ask: id.to_string(),
        method: approved.map_or_else(|| method_sha256(&reply.method), str::to_string),
        snapshot_sha256: snap.held().sha256().to_string(),
        ms: result.ms,
        rows_band: result.row_band.clone(),
        calculator: CALC_LABEL,
        landlock_abi: conf.landlock_abi,
        seccomp: conf.seccomp,
        netns: conf.netns,
        answer_sha256: checked.as_ref().ok().map(|(f, _)| sha256_hex(&f.text)),
    };
    record(ctx, st, r, RUN_UNRECORDED).await?;
    let (filled, report) = match checked {
        Ok(x) => x,
        Err((c, reason)) => {
            return Ok(after_run_refusal(ctx, id, st, c, reason, line, lang).await);
        }
    };
    let shown = u64::try_from(result.rows.len()).unwrap_or(u64::MAX);
    let note = result
        .truncated
        .then(|| cap_note(shown, result.total_rows.unwrap_or(shown), lang));
    let n = |x: usize| u32::try_from(x).unwrap_or(u32::MAX);
    Ok(Step::Answer {
        text: filled.text,
        method_line: line,
        cap_note: note,
        footer: footer(approved, st.sent.personal_values, report.numbers, lang),
        checked: Checked {
            numbers: n(report.numbers),
            from_calc: n(report.from_calc),
        },
    })
}

/// Fill the template with the user's own words for each entity (R48-2b)
/// and check the answer (ruling F-f: the coverage runs again): the filled
/// answer and the checker's count, or the refusal's code and reason.
fn check_answer(
    st: &AskState,
    d: &Draft,
    v: &Validated,
    reply: &PlanReply,
    result: &ResultSet,
) -> Result<(Filled, checker::CheckReport), (&'static str, String)> {
    let schema = st.snapshot.schema();
    let ap = answer_params(d, schema);
    let failed = |_| (code::CHECK_FAILED, FILL_FAILED.to_string());
    let t = parse_template(&reply.template, &v.output_columns(), &ap, st.opts.list_cap)
        .map_err(failed)?;
    let f = fill(&t, result, &ap, d.lang).map_err(failed)?;
    match checker::check(v, &t, &ap, &f, &d.original, d.lang) {
        Ok(rep) => Ok((f, rep)),
        Err(e) if e.class == ErrorClass::ParamMisuse => Err((code::PARAM_MISUSE, e.reason)),
        Err(e) => Err((code::CHECK_FAILED, e.reason)),
    }
}

/// A calculator refusal as the user sees it: (code, reason). The
/// `empty_for_key` reason names the entity by the user's words only
/// (R48-2b); `identifier_output` is the reveal hook (R-C5).
fn calc_refusal(o: &Outcome<'_>, d: &Draft, schema: &Schema) -> (&'static str, String) {
    let class_of = |c: &str| ErrorClass::from_str(c).map_or("runtime_error", |c| c.as_str());
    match o {
        Outcome::EmptyResult { .. } => (code::EMPTY_RESULT, empty_result_reason(d.lang).into()),
        Outcome::SnapshotMismatch => (code::SNAPSHOT_MISMATCH, calc::SNAPSHOT_MISMATCH_TEXT.into()),
        Outcome::TimeCap => (code::TIME_CAP, TIME_CAP_TEXT.into()),
        Outcome::Refused {
            class: "check_failed",
            empty_for: Some(p),
        } => (code::EMPTY_FOR_KEY, empty_for_key_reason(d, schema, p)),
        Outcome::Refused {
            class: "check_failed",
            empty_for: None,
        } => (code::CHECK_FAILED, SELF_CHECK_FAILED.into()),
        Outcome::Refused { class, .. } if class_of(class) == "identifier_output" => {
            (code::IDENTIFIER_OUTPUT, IDENTIFIER_OUTPUT_REASON.into())
        }
        Outcome::Refused { class, .. } => (
            code::CALC_REFUSED,
            format!("the calculator refused the method ({})", class_of(class)),
        ),
        // Handled by the caller.
        Outcome::Ran { .. } | Outcome::SandboxUnavailable => {
            (code::CALC_REFUSED, SANDBOX_TEXT.into())
        }
    }
}

/// `blind_check_refused` with a fixed code (never the reason, which can
/// name the user's words). A failed write is logged; the refusal stands.
async fn refused_record(ctx: &Ctx, id: &str, st: &AskState, reason: &'static str) {
    let r = BlindRecord::CheckRefused {
        ask: id.to_string(),
        reason: reason.to_string(),
    };
    if record(ctx, st, r, UNRECORDED_NOTHING_SENT).await.is_err() {
        eprintln!("saiifed: blind: a refusal after the run was not recorded");
    }
}

/// A refusal after the run (R48-4): its head, the reason, the method line.
async fn after_run_refusal(
    ctx: &Ctx,
    id: &str,
    st: &AskState,
    c: &'static str,
    reason: String,
    line: String,
    lang: Lang,
) -> Step {
    refused_record(ctx, id, st, c).await;
    Step::Refused {
        code: c,
        head: head_no_answer(lang).to_string(),
        reason,
        method_line: Some(line),
    }
}

/// Lowercase hex SHA-256 of `s`.
fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    crate::api_ops::hex(&Sha256::digest(s.as_bytes()))
}
