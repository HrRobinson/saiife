//! The Data Shield audit records (plan 47 R47-10, spec §2.1.5). Each record
//! holds ids, hashes, counts and labels, never a dataset value. Before one
//! is written every string field is scanned against the dataset's
//! `KnownIndex`; a hit (or a failed lookup, which fails closed) drops that
//! field and writes a `blind_log_scrubbed` record naming the record kind and
//! the field. A record the audit writer refuses is an error to the caller,
//! so a send can be blocked when it cannot be recorded (R47-8).

use crate::ops::Ctx;
use saiife_shield::firewall::text_has_known;
use saiife_shield::index::{IndexKey, KnownIndex};
use saiife_shield::norm::normalize;
use saiife_shield::schema::{ColumnClass, Lang};
use serde_json::{json, Value};

/// What Data Shield records. The `&'static str` fields are fixed labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlindRecord {
    Ask {
        ask: String,
        dataset: String,
        lang: Lang,
        /// Parameterized: symbols as stand-ins.
        question: String,
        session: String,
        approved_method: Option<String>,
    },
    Resolve {
        ask: String,
        /// (tag, candidates).
        params: Vec<(String, u32)>,
        did_you_mean: u32,
        kept_names: u32,
    },
    Preview {
        ask: String,
        sha256: String,
        /// `shown`, `accepted`, `stopped` or `auto`.
        outcome: &'static str,
        fragments: u32,
    },
    Send {
        ask: String,
        envelope_sha256: String,
        body_sha256: String,
        prompt_sha256: String,
        model: String,
        tables: u32,
        synthetic_rows: u32,
        params: u32,
        personal_values: u32,
        k: u32,
        attempt: u32,
    },
    Receive {
        ask: String,
        status: u16,
        bytes: u64,
        reply_sha256: String,
        leak: bool,
        stop_reason: String,
    },
    Run {
        ask: String,
        /// A sha256 or an approved id.
        method: String,
        snapshot_sha256: String,
        ms: u64,
        rows_band: String,
        /// `CALC_LABEL`.
        calculator: &'static str,
        landlock_abi: u32,
        seccomp: bool,
        netns: bool,
    },
    CheckRefused {
        ask: String,
        /// A class or a checker reason.
        reason: String,
    },
    Approve {
        method: String,
        version: u32,
        dataset: String,
        template_sha256: String,
        touch: String,
        /// `add` or `remove`.
        action: &'static str,
    },
    Keys {
        dataset: String,
        /// `create`, `rotate` or `delete`.
        action: &'static str,
        version: u32,
        touch: Option<String>,
    },
    Refresh {
        dataset: String,
        snapshot_sha256: String,
        /// (table, rows).
        rows: Vec<(String, String)>,
        index_entries: u64,
        ms: u64,
        suspended: Vec<String>,
        first: bool,
    },
    Loosen {
        dataset: String,
        column: String,
        from: ColumnClass,
        to: ColumnClass,
        touch: String,
    },
    Name {
        ask: String,
        touch: String,
        /// [`name_sha256`].
        name_sha256: String,
    },
}

/// The record's kind, its fields (the `ask`, `dataset` and `session` ones
/// first) and the dataset or ask id that goes in `input`.
fn fields(r: BlindRecord) -> (&'static str, Vec<(&'static str, Value)>) {
    let lang = |l: Lang| match l {
        Lang::En => "en",
        Lang::Da => "da",
    };
    let class = |c: ColumnClass| serde_json::to_value(c).unwrap_or(Value::Null);
    match r {
        BlindRecord::Ask {
            ask,
            dataset,
            lang: l,
            question,
            session,
            approved_method,
        } => (
            "blind_ask",
            vec![
                ("ask", json!(ask)),
                ("dataset", json!(dataset)),
                ("lang", json!(lang(l))),
                ("question", json!(question)),
                ("session", json!(session)),
                ("approved_method", json!(approved_method)),
            ],
        ),
        BlindRecord::Resolve {
            ask,
            params,
            did_you_mean,
            kept_names,
        } => (
            "blind_resolve",
            vec![
                ("ask", json!(ask)),
                ("params", json!(params)),
                ("did_you_mean", json!(did_you_mean)),
                ("kept_names", json!(kept_names)),
            ],
        ),
        BlindRecord::Preview {
            ask,
            sha256,
            outcome,
            fragments,
        } => (
            "blind_preview",
            vec![
                ("ask", json!(ask)),
                ("sha256", json!(sha256)),
                ("outcome", json!(outcome)),
                ("fragments", json!(fragments)),
            ],
        ),
        BlindRecord::Send {
            ask,
            envelope_sha256,
            body_sha256,
            prompt_sha256,
            model,
            tables,
            synthetic_rows,
            params,
            personal_values,
            k,
            attempt,
        } => (
            "blind_send",
            vec![
                ("ask", json!(ask)),
                ("envelope_sha256", json!(envelope_sha256)),
                ("body_sha256", json!(body_sha256)),
                ("prompt_sha256", json!(prompt_sha256)),
                ("model", json!(model)),
                ("tables", json!(tables)),
                ("synthetic_rows", json!(synthetic_rows)),
                ("params", json!(params)),
                ("personal_values", json!(personal_values)),
                ("k", json!(k)),
                ("attempt", json!(attempt)),
            ],
        ),
        BlindRecord::Receive {
            ask,
            status,
            bytes,
            reply_sha256,
            leak,
            stop_reason,
        } => (
            "blind_receive",
            vec![
                ("ask", json!(ask)),
                ("status", json!(status)),
                ("bytes", json!(bytes)),
                ("reply_sha256", json!(reply_sha256)),
                ("leak", json!(leak)),
                ("stop_reason", json!(stop_reason)),
            ],
        ),
        BlindRecord::Run {
            ask,
            method,
            snapshot_sha256,
            ms,
            rows_band,
            calculator,
            landlock_abi,
            seccomp,
            netns,
        } => (
            "blind_run",
            vec![
                ("ask", json!(ask)),
                ("method", json!(method)),
                ("snapshot_sha256", json!(snapshot_sha256)),
                ("ms", json!(ms)),
                ("rows_band", json!(rows_band)),
                ("calculator", json!(calculator)),
                ("landlock_abi", json!(landlock_abi)),
                ("seccomp", json!(seccomp)),
                ("netns", json!(netns)),
            ],
        ),
        BlindRecord::CheckRefused { ask, reason } => (
            "blind_check_refused",
            vec![("ask", json!(ask)), ("reason", json!(reason))],
        ),
        BlindRecord::Approve {
            method,
            version,
            dataset,
            template_sha256,
            touch,
            action,
        } => (
            "blind_approve",
            vec![
                ("dataset", json!(dataset)),
                ("method", json!(method)),
                ("version", json!(version)),
                ("template_sha256", json!(template_sha256)),
                ("touch", json!(touch)),
                ("action", json!(action)),
            ],
        ),
        BlindRecord::Keys {
            dataset,
            action,
            version,
            touch,
        } => (
            "blind_keys",
            vec![
                ("dataset", json!(dataset)),
                ("action", json!(action)),
                ("version", json!(version)),
                ("touch", json!(touch)),
            ],
        ),
        BlindRecord::Refresh {
            dataset,
            snapshot_sha256,
            rows,
            index_entries,
            ms,
            suspended,
            first,
        } => (
            "blind_refresh",
            vec![
                ("dataset", json!(dataset)),
                ("snapshot_sha256", json!(snapshot_sha256)),
                ("rows", json!(rows)),
                ("index_entries", json!(index_entries)),
                ("ms", json!(ms)),
                ("suspended", json!(suspended)),
                ("first", json!(first)),
            ],
        ),
        BlindRecord::Loosen {
            dataset,
            column,
            from,
            to,
            touch,
        } => (
            "blind_loosen",
            vec![
                ("dataset", json!(dataset)),
                ("column", json!(column)),
                ("from", class(from)),
                ("to", class(to)),
                ("touch", json!(touch)),
            ],
        ),
        BlindRecord::Name {
            ask,
            touch,
            name_sha256,
        } => (
            "blind_name",
            vec![
                ("ask", json!(ask)),
                ("touch", json!(touch)),
                ("name_sha256", json!(name_sha256)),
            ],
        ),
    }
}

/// The keyed hash of a name: HMAC-SHA256 under the dataset's index key over
/// the normalized name (case, accents and spacing folded as the index does),
/// hex. Equal names link locally; without the key they cannot be read back.
pub fn name_sha256(key: &IndexKey, name: &str) -> String {
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key.0[..]);
    let mut c = ring::hmac::Context::with_key(&k);
    c.update(b"saiife-blind-name-v1\0");
    c.update(normalize(name).as_bytes());
    crate::api_ops::hex(c.sign().as_ref())
}

/// Every string inside `v`, nested ones too.
fn strings<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
    match v {
        Value::String(s) => out.push(s),
        Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
        Value::Object(o) => o.values().for_each(|x| strings(x, out)),
        _ => {}
    }
}

/// Why a field is dropped: a hit, or a lookup that failed (closed).
fn scrub_reason(index: Option<&KnownIndex>, v: &Value) -> Option<&'static str> {
    let index = index?;
    let mut all = Vec::new();
    strings(v, &mut all);
    let mut failed = false;
    for s in all {
        match text_has_known(index, s) {
            Ok(false) => {}
            Ok(true) => return Some("known_value"),
            Err(_) => failed = true,
        }
    }
    failed.then_some("scan_failed")
}

/// Writes `r` as `uid`'s record: the scrub, then the audit writer. Fields
/// that hit the dataset's index are left out and a `blind_log_scrubbed`
/// record says which. Err when the writer refuses any record (the caller
/// decides; a send must not go).
///
/// `input` is the kind and the dataset (`blind_keys crm`); a record that has
/// no dataset field (an ask's steps) names its ask id instead. It is never a
/// question.
pub async fn write(
    ctx: &Ctx,
    uid: u32,
    r: BlindRecord,
    index: Option<&KnownIndex>,
) -> Result<(), String> {
    let (kind, fields) = fields(r);
    let mut kept: Vec<(&str, Value)> = Vec::new();
    let mut dropped: Vec<(&str, &str)> = Vec::new();
    for (name, v) in fields {
        match scrub_reason(index, &v) {
            None => kept.push((name, v)),
            Some(why) => dropped.push((name, why)),
        }
    }
    let user = ctx.name_of(uid).await;
    let base = |kind: &str, input: &str| {
        let mut rec = ctx.record(kind, input);
        rec.uid = Some(uid);
        rec.user = user.clone();
        rec
    };
    let id_of = |f: &str| {
        kept.iter()
            .find(|(n, _)| *n == f)
            .and_then(|(_, v)| v.as_str())
    };
    let input = match id_of("dataset").or_else(|| id_of("ask")) {
        Some(id) => format!("{kind} {id}"),
        None => kind.to_string(),
    };
    for (field, why) in &dropped {
        let mut rec = base("blind_log_scrubbed", &format!("blind_log_scrubbed {kind}"));
        rec.extra.insert("scrubbed_kind".into(), kind.into());
        rec.extra.insert("field".into(), (*field).into());
        rec.extra.insert("cause".into(), (*why).into());
        ctx.writer.append(rec).await?;
    }
    let mut rec = base(kind, &input);
    for (name, v) in kept {
        // `session` and `reason` are fields of the record itself; a second
        // key of the same name in `extra` would write a line that cannot be
        // read back.
        if name == "session" {
            rec.session = v.as_str().map(str::to_string);
        } else if name == "reason" {
            rec.reason = v.as_str().map(str::to_string);
        } else {
            rec.extra.insert(name.into(), v);
        }
    }
    ctx.writer.append(rec).await?;
    Ok(())
}
