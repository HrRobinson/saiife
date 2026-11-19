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
/// `Debug` prints the kind only (a `question` or a column is not for logs).
#[derive(Clone, PartialEq, Eq)]
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
        /// [`preview_mac`] of the preview text (it holds the user's words
        /// and `show` values: never a bare hash).
        preview_mac: String,
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
        /// [`answer_mac`] of the answer shown (R48-4, spec §6.5: the text
        /// itself is never logged; a bare hash of a short answer could be
        /// guessed back); none when it was refused.
        answer_mac: Option<String>,
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
        /// A fixed label (`dataset removed`), or none.
        reason: Option<&'static str>,
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

impl BlindRecord {
    /// The record's kind (its `kind` in the log).
    pub fn kind(&self) -> &'static str {
        match self {
            BlindRecord::Ask { .. } => "blind_ask",
            BlindRecord::Resolve { .. } => "blind_resolve",
            BlindRecord::Preview { .. } => "blind_preview",
            BlindRecord::Send { .. } => "blind_send",
            BlindRecord::Receive { .. } => "blind_receive",
            BlindRecord::Run { .. } => "blind_run",
            BlindRecord::CheckRefused { .. } => "blind_check_refused",
            BlindRecord::Approve { .. } => "blind_approve",
            BlindRecord::Keys { .. } => "blind_keys",
            BlindRecord::Refresh { .. } => "blind_refresh",
            BlindRecord::Loosen { .. } => "blind_loosen",
            BlindRecord::Name { .. } => "blind_name",
        }
    }
}

impl std::fmt::Debug for BlindRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlindRecord")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
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
            preview_mac,
            outcome,
            fragments,
        } => (
            "blind_preview",
            vec![
                ("ask", json!(ask)),
                ("preview_mac", json!(preview_mac)),
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
            answer_mac,
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
                ("answer_mac", json!(answer_mac)),
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
            reason,
        } => (
            "blind_keys",
            vec![
                ("dataset", json!(dataset)),
                ("action", json!(action)),
                ("version", json!(version)),
                ("touch", json!(touch)),
                ("reason", json!(reason)),
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

/// HMAC-SHA256 under the dataset's index key (the blind key store's, as
/// [`name_sha256`]) over a domain label and the exact text, hex. For text
/// that is secret and easy to guess (an answer, a preview): an audit
/// reader without the key cannot confirm a guess offline; with it, equal
/// texts link. The labels keep the three uses apart.
fn audit_mac(key: &IndexKey, domain: &[u8], text: &str) -> String {
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key.0[..]);
    let mut c = ring::hmac::Context::with_key(&k);
    c.update(domain);
    c.update(text.as_bytes());
    crate::api_ops::hex(c.sign().as_ref())
}

/// `blind_run.answer_mac`: [`audit_mac`] of the answer text shown.
pub fn answer_mac(key: &IndexKey, answer: &str) -> String {
    audit_mac(key, b"saiife-blind-answer-v1\0", answer)
}

/// `blind_preview.preview_mac`: [`audit_mac`] of the preview text.
pub fn preview_mac(key: &IndexKey, preview: &str) -> String {
    audit_mac(key, b"saiife-blind-preview-v1\0", preview)
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

/// The fields of `r` that can hold free text (a question, a reason, a touch
/// or table name, a server's stop reason). With no index to scan against
/// these are dropped; every other string is a fixed label, an id or a hash.
/// Exhaustive on purpose: a new variant must say which of its fields are
/// free text.
fn free_text(r: &BlindRecord) -> &'static [&'static str] {
    match r {
        BlindRecord::Ask { .. } => &["question"],
        BlindRecord::Resolve { .. } => &[],
        BlindRecord::Preview { .. } => &[],
        BlindRecord::Send { .. } => &[],
        BlindRecord::Receive { .. } => &["stop_reason"],
        BlindRecord::Run { .. } => &[],
        BlindRecord::CheckRefused { .. } => &["reason"],
        BlindRecord::Approve { .. } => &["touch"],
        BlindRecord::Keys { .. } => &["touch"],
        BlindRecord::Refresh { .. } => &["rows", "suspended"],
        BlindRecord::Loosen { .. } => &["column", "touch"],
        BlindRecord::Name { .. } => &["touch"],
    }
}

/// The strings of a field to scan. A `rows` field is (table, count) pairs:
/// the count is a number written as text and is exempt by name; the table
/// is scanned.
fn scan_strings<'a>(name: &str, v: &'a Value, out: &mut Vec<&'a str>) {
    if name == "rows" {
        if let Value::Array(pairs) = v {
            for p in pairs {
                if let Some(t) = p.get(0) {
                    strings(t, out);
                }
            }
            return;
        }
    }
    strings(v, out);
}

/// Why a field is dropped: a hit, a lookup that failed (closed), or no
/// index to scan with for a field that can hold free text.
fn scrub_reason(
    index: Option<&KnownIndex>,
    free: bool,
    name: &str,
    v: &Value,
) -> Option<&'static str> {
    let mut all = Vec::new();
    scan_strings(name, v, &mut all);
    let Some(index) = index else {
        return (free && !all.is_empty()).then_some("no_index");
    };
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

/// Writes `r` as `uid`'s record about `dataset`: the scrub, then the audit
/// writer. Fields that hit the dataset's index are left out and a
/// `blind_log_scrubbed` record says which. With no index the fields that can
/// hold free text are dropped the same way (fail closed). Err when the
/// writer refuses any record (the caller decides; a send must not go).
///
/// `input` is `<kind> <dataset>` for every record, the marker too, never a
/// question; a record without its own dataset field gets `extra.dataset`.
pub async fn write(
    ctx: &Ctx,
    uid: u32,
    dataset: &str,
    r: BlindRecord,
    index: Option<&KnownIndex>,
) -> Result<(), String> {
    let free = free_text(&r);
    let (kind, fields) = fields(r);
    let mut kept: Vec<(&str, Value)> = Vec::new();
    let mut dropped: Vec<(&str, &str)> = Vec::new();
    for (name, v) in fields {
        match scrub_reason(index, free.contains(&name), name, &v) {
            None => kept.push((name, v)),
            Some(why) => dropped.push((name, why)),
        }
    }
    let user = ctx.name_of(uid).await;
    let base = |kind: &str| {
        let mut rec = ctx.record(kind, &format!("{kind} {dataset}"));
        rec.uid = Some(uid);
        rec.user = user.clone();
        rec
    };
    for (field, why) in &dropped {
        let mut rec = base("blind_log_scrubbed");
        rec.extra.insert("scrubbed_kind".into(), kind.into());
        rec.extra.insert("field".into(), (*field).into());
        rec.extra.insert("cause".into(), (*why).into());
        rec.extra.insert("dataset".into(), dataset.into());
        ctx.writer.append(rec).await?;
    }
    let mut rec = base(kind);
    if !kept.iter().any(|(n, _)| *n == "dataset") {
        rec.extra.insert("dataset".into(), dataset.into());
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_prints_the_kind_only() {
        let r = BlindRecord::Ask {
            ask: "ask-1".into(),
            dataset: "crm".into(),
            lang: Lang::En,
            question: "revenue of Søren Østergård".into(),
            session: "sess-1".into(),
            approved_method: None,
        };
        let d = format!("{r:?}");
        assert_eq!(d, "BlindRecord { kind: \"blind_ask\", .. }");
        assert!(!d.contains("Søren"), "{d}");
        // The kinds agree with what is written.
        assert_eq!(r.kind(), fields(r.clone()).0);
        let l = BlindRecord::Loosen {
            dataset: "crm".into(),
            column: "customers.city".into(),
            from: ColumnClass::Quasi,
            to: ColumnClass::Public,
            touch: "t".into(),
        };
        assert!(!format!("{l:?}").contains("city"));
        assert_eq!(l.kind(), fields(l.clone()).0);
    }
}
