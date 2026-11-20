//! `saiife blind ask` (plan 48 T4): `blind.ask`, then each step shown and
//! answered (`blind.ask.answer`) until an answer or a refusal. A kept name
//! takes a `blind:name` touch: `blind.touch.begin`, the key, then
//! `blind.touch.commit` on a new connection (a touch may take 120 s).
//!
//! The interactive parts (pick lists, "did you mean", the preview and the
//! prompts) go to stderr; the answer, a refusal and the envelope
//! (`--show-sent`) go to stdout. Every daemon string is sanitized, line by
//! line.
//!
//! An ask id is used only while its step asks for an answer: the
//! `refreshing` and `--judgment` steps end the ask, and their ids were never
//! kept by the daemon (T1 M3), so nothing is sent on them.

use super::imp::{args, call, s, Args as CallArgs, Stop, ASK_TIMEOUT, READ_TIMEOUT};
use super::Prompter;
use crate::broker::Target;
use crate::text::sanitize;
use saiife_shield::schema::Lang;
use saiife_touch::{TouchError, TouchRequest};
use serde_json::{json, Value};
use std::process::ExitCode;

/// R48-3: no terminal and no `--yes`.
pub(crate) const NEEDS_ANSWER: &str =
    "the method preview needs an answer: run saiife blind ask in a terminal, or pass --yes";
/// The most steps one ask may take (a daemon that never ends one is cut).
const MAX_STEPS: usize = 32;

/// The `ask` flags.
pub(crate) struct Args {
    pub(crate) question: String,
    pub(crate) judgment: bool,
    pub(crate) show_sent: bool,
    pub(crate) dataset: Option<String>,
    pub(crate) new_session: bool,
    pub(crate) yes: bool,
    pub(crate) limit: Option<u32>,
    pub(crate) lang: Option<String>,
}

/// The language of the prompts: `--lang`, else the question's.
fn lang_of(a: &Args) -> Result<Lang, Stop> {
    match a.lang.as_deref() {
        None => Ok(saiife_shield::lang::detect_lang(&a.question)),
        Some("en") => Ok(Lang::En),
        Some("da") => Ok(Lang::Da),
        Some(_) => Err(Stop::Refused("--lang must be en or da".into())),
    }
}

/// A daemon text as terminal lines, each sanitized (a list answer keeps
/// its lines).
fn lines(t: &str) -> Vec<String> {
    t.split('\n').map(sanitize).collect()
}

fn say(t: &str) {
    for l in lines(t) {
        outln!("{l}");
    }
}

fn tell(t: &str) {
    for l in lines(t) {
        eprintln!("{l}");
    }
}

/// `customer` -> `customers` (the English pick header).
pub(super) fn plural(word: &str) -> String {
    let consonant_y = word.len() > 1
        && word.ends_with('y')
        && !word[..word.len() - 1].ends_with(['a', 'e', 'i', 'o', 'u']);
    if consonant_y {
        format!("{}ies", &word[..word.len() - 1])
    } else if word.ends_with(['s', 'x']) || word.ends_with("sh") || word.ends_with("ch") {
        format!("{word}es")
    } else {
        format!("{word}s")
    }
}

/// A yes to a `(y/N)` prompt: y, yes, j, ja (any case).
pub(super) fn is_yes(a: &str) -> bool {
    matches!(a.to_lowercase().as_str(), "y" | "yes" | "j" | "ja")
}

/// A yes to `Run it? (Y/n)`: empty is yes.
pub(super) fn is_run(a: &str) -> bool {
    a.is_empty() || is_yes(a)
}

/// The pick header (fixed values).
fn found_line(lang: Lang, n: usize, word: &str, written: &str) -> String {
    match lang {
        Lang::En => format!("Found {n} {} named {written}:", plural(word)),
        Lang::Da => format!("Fandt {n} {word} med navnet {written}:"),
    }
}

fn which_prompt(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Which one? ",
        Lang::Da => "Hvilken? ",
    }
}

fn did_you_mean_prompt(lang: Lang, word: &str, written: &str, display: &str) -> String {
    match lang {
        Lang::En => format!("No {word} named \"{written}\". Did you mean {display}? (y/N) "),
        Lang::Da => format!("Ingen {word} ved navn \"{written}\". Mente du {display}? (j/N) "),
    }
}

fn keep_name_prompt(name: &str, dataset: &str) -> String {
    format!(
        "\"{name}\" is not in {dataset}. Send it as plain text to the planner? This needs a touch (blind:name). (y/N) "
    )
}

pub(super) fn run_prompt(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Run it? (Y/n) ",
        Lang::Da => "Kør den? (J/n) ",
    }
}

/// The approve hint (fixed values), for approvers only.
pub(crate) fn approve_hint(ask: &str) -> String {
    format!("approve this method for reuse: saiife blind methods approve {ask}")
}

/// What one ask knows of its dataset, from `blind.status`: the name (the
/// flag, else the only one the user may ask) and whether the user approves
/// for it. `None` when it cannot tell.
struct Mine {
    name: Option<String>,
    approver: bool,
}

fn mine(t: &Target, given: Option<&str>) -> Mine {
    let none = Mine {
        name: given.map(str::to_string),
        approver: false,
    };
    let Ok(v) = call(t, "blind.status", serde_json::Map::new(), READ_TIMEOUT) else {
        return none;
    };
    let list: Vec<&Value> = v
        .get("datasets")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .collect();
    let role = |d: &Value, k: &str| d["role"].get(k).and_then(Value::as_bool) == Some(true);
    let pick = match given {
        Some(g) => list.into_iter().find(|d| s(d, "name") == g),
        None => {
            let asks: Vec<&Value> = list
                .into_iter()
                .filter(|d| role(d, "user") || role(d, "approver"))
                .collect();
            match asks.as_slice() {
                [one] => Some(*one),
                _ => None,
            }
        }
    };
    match pick {
        Some(d) => Mine {
            name: Some(s(d, "name").to_string()),
            approver: role(d, "approver"),
        },
        None => none,
    }
}

/// The ask's reply: its id and step.
pub(super) fn reply(v: serde_json::Map<String, Value>) -> Result<(String, Value), Stop> {
    let id = v
        .get("ask")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Stop::Unavailable("the saiife daemon sent no ask id".into()))?
        .to_string();
    let step = v.get("step").cloned().unwrap_or(Value::Null);
    Ok((id, step))
}

pub(super) fn answer(t: &Target, id: &str, a: Value) -> Result<Value, Stop> {
    let v = call(
        t,
        "blind.ask.answer",
        args([("ask", json!(id)), ("answer", a)]),
        ASK_TIMEOUT,
    )?;
    Ok(reply(v)?.1)
}

/// Ends an ask that cannot be answered here (no terminal): every pending
/// step answered "no" until the daemon ends it, so its slot is freed. What
/// the daemon says is not shown: the caller says why.
pub(super) fn end_quietly(t: &Target, id: &str, mut step: Value) {
    for _ in 0..4 {
        let a = match s(&step, "kind") {
            "pick" => json!({"pick": 0}),
            "did_you_mean" => json!({"did_you_mean": false}),
            "keep_name" => json!({"keep_name": false}),
            "preview" => json!({"run": false}),
            _ => return,
        };
        match answer(t, id, a) {
            Ok(s) => step = s,
            Err(_) => return,
        }
    }
}

/// The envelope (`--show-sent`) on stdout: a header, then the JSON as sent
/// (ASCII-escaped, the same data).
pub(super) fn print_envelope(step: &Value) {
    let Some(e) = step.get("envelope").and_then(Value::as_str) else {
        return;
    };
    outln!("── sent to the planner:");
    match serde_json::from_str::<Value>(e) {
        Ok(v) => outln!("{}", crate::box_cmd::ascii_json(&v)),
        Err(_) => outln!("{}", sanitize(e)),
    }
}

/// The `TouchRequest` of a `blind.touch.begin` answer.
fn touch_request(b: &serde_json::Map<String, Value>) -> Result<(String, TouchRequest), Stop> {
    let rid = b
        .get("request_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()))
        .ok_or_else(|| Stop::Unavailable("the saiife daemon sent no request id".into()))?;
    let r: TouchRequest = serde_json::from_value(b.get("touch").cloned().unwrap_or(Value::Null))
        .map_err(|e| {
            Stop::Unavailable(format!(
                "the saiife daemon sent a touch request this saiife cannot read: {e}"
            ))
        })?;
    Ok((rid.to_string(), r))
}

/// A `blind:*` touch (plan 48 T3's flow): the key first (no key, no
/// challenge spent), `blind.touch.begin` with `begin`, the summary on
/// stderr, the assertion, then `blind.touch.commit` on a new connection (a
/// touch may take 120 s). The commit's answer.
pub(super) fn touch(t: &Target, begin: CallArgs) -> Result<serde_json::Map<String, Value>, Stop> {
    let key = crate::touch_cmd::pick().map_err(Stop::Unavailable)?;
    let b = call(t, "blind.touch.begin", begin, READ_TIMEOUT)?;
    let (rid, r) = touch_request(&b)?;
    eprintln!(
        "saiife: touch your key to {} (code {})",
        sanitize(&r.summary),
        sanitize(&r.short_code)
    );
    let asr = key.request(&r).map_err(|e| match e {
        TouchError::Unavailable => Stop::Unavailable(e.to_string()),
        other => Stop::Refused(other.to_string()),
    })?;
    let asr = serde_json::to_value(asr)
        .map_err(|e| Stop::Unavailable(format!("cannot encode the touch: {e}")))?;
    call(
        t,
        "blind.touch.commit",
        args([("request_id", json!(rid)), ("assertion", asr)]),
        ASK_TIMEOUT,
    )
}

/// Keep `name` as plain text: a `blind:name` touch, then the ask goes on
/// (the commit answers its next step).
fn keep_name_touch(t: &Target, id: &str, name: &str) -> Result<Value, Stop> {
    let v = touch(
        t,
        args([
            ("purpose", json!("name")),
            ("ask", json!(id)),
            ("name", json!(name)),
        ]),
    )?;
    Ok(reply(v)?.1)
}

/// What the loop does after a step.
enum Next {
    Answer(Value),
    /// The commit of a kept name gave the next step itself.
    Step(Value),
    Done(ExitCode),
}

/// One step: shown, and answered when it asks for an answer.
fn handle(
    t: &Target,
    a: &Args,
    lang: Lang,
    id: &str,
    step: &Value,
    p: &mut dyn Prompter,
) -> Result<Next, Stop> {
    match s(step, "kind") {
        "pick" => {
            let cands: Vec<&Value> = step
                .get("candidates")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .collect();
            let head = found_line(
                lang,
                cands.len(),
                &sanitize(s(step, "word")),
                &sanitize(s(step, "written")),
            );
            if !p.is_interactive() {
                // R48-3: the count only.
                end_quietly(t, id, step.clone());
                return Err(Stop::Refused(format!(
                    "{} choosing one needs a terminal: run saiife blind ask in a terminal",
                    head
                )));
            }
            eprintln!("{head}");
            for c in &cands {
                let n = c.get("n").and_then(Value::as_u64).unwrap_or(0);
                eprintln!("  {n}) {}", sanitize(s(c, "label")));
            }
            if step.get("too_many").and_then(Value::as_bool) == Some(true) {
                match lang {
                    Lang::En => eprintln!("  (and more: 0 for none of these)"),
                    Lang::Da => eprintln!("  (og flere: 0 for ingen af dem)"),
                }
            }
            // A number from the list, or 0 for none of these; no answer
            // is none.
            let n = loop {
                let got = match p.line(which_prompt(lang)) {
                    Ok(l) => l,
                    Err(_) => break 0,
                };
                match got.parse::<usize>() {
                    Ok(n) if n <= cands.len() => break n,
                    _ => eprintln!("type a number from 1 to {} (0: none of these)", cands.len()),
                }
            };
            Ok(Next::Answer(json!({"pick": n})))
        }
        "did_you_mean" => {
            if !p.is_interactive() {
                end_quietly(t, id, step.clone());
                return Err(Stop::Refused(format!(
                    "no {} named \"{}\" (one close match): choosing it needs a terminal: run saiife blind ask in a terminal",
                    sanitize(s(step, "word")),
                    sanitize(s(step, "written"))
                )));
            }
            let q = did_you_mean_prompt(
                lang,
                &sanitize(s(step, "word")),
                &sanitize(s(step, "written")),
                &sanitize(s(step, "suggestion")),
            );
            let yes = p.line(&q).map(|l| is_yes(&l)).unwrap_or(false);
            Ok(Next::Answer(json!({"did_you_mean": yes})))
        }
        "keep_name" => {
            let name = s(step, "name").to_string();
            if !p.is_interactive() {
                end_quietly(t, id, step.clone());
                return Err(Stop::Refused(
                    "a name that is not in the dataset needs a yes and a touch: run saiife blind ask in a terminal".into(),
                ));
            }
            let ds = mine(t, a.dataset.as_deref())
                .name
                .unwrap_or_else(|| "the dataset".into());
            let q = keep_name_prompt(&sanitize(&name), &sanitize(&ds));
            if p.line(&q).map(|l| is_yes(&l)).unwrap_or(false) {
                return match keep_name_touch(t, id, &name) {
                    Ok(next) => Ok(Next::Step(next)),
                    // T4 M2: a key that is missing or said no, or a commit
                    // that failed, ends the ask (best effort) instead of
                    // holding its slot until it expires.
                    Err(e) => {
                        end_quietly(t, id, step.clone());
                        Err(e)
                    }
                };
            }
            Ok(Next::Answer(json!({"keep_name": false})))
        }
        "preview" => {
            print_envelope(step);
            tell(s(step, "text"));
            if let Some(says) = step.get("planner_says").and_then(Value::as_str) {
                eprintln!("the planner says: {}", sanitize(says));
            }
            if a.yes {
                return Ok(Next::Answer(json!({"run": true})));
            }
            if !p.is_interactive() {
                end_quietly(t, id, step.clone());
                return Err(Stop::Refused(NEEDS_ANSWER.into()));
            }
            let run = p
                .line(run_prompt(lang))
                .map(|l| is_run(&l))
                .unwrap_or(false);
            Ok(Next::Answer(json!({"run": run})))
        }
        "answer" => {
            print_envelope(step);
            say(s(step, "text"));
            if let Some(n) = step.get("cap_note").and_then(Value::as_str) {
                say(n);
            }
            say(s(step, "method_line"));
            say(s(step, "footer"));
            // R48-6: a method approve would take (the daemon says so,
            // T4 M1), to approvers only.
            let approvable = step.get("approvable").and_then(Value::as_bool) == Some(true);
            if approvable && mine(t, a.dataset.as_deref()).approver {
                eprintln!("{}", approve_hint(&sanitize(id)));
            }
            Ok(Next::Done(ExitCode::SUCCESS))
        }
        "refused" => {
            print_envelope(step);
            // R-C5: the `identifier_output` reason is printed as given (it
            // is `sql::IDENTIFIER_OUTPUT_REASON`); every code the same way.
            say(s(step, "head"));
            say(s(step, "reason"));
            if let Some(m) = step.get("method_line").and_then(Value::as_str) {
                say(m);
            }
            Ok(Next::Done(ExitCode::from(2)))
        }
        // The dataset is being rebuilt; the ask id was never kept (T1 M3).
        "refreshing" => {
            say(s(step, "text"));
            Ok(Next::Done(ExitCode::from(5)))
        }
        other => Err(Stop::Unavailable(format!(
            "the saiife daemon sent a step this saiife cannot show ({})",
            sanitize(other)
        ))),
    }
}

/// `saiife blind ask`.
pub(crate) fn run(t: &Target, a: Args, p: &mut dyn Prompter) -> Result<ExitCode, Stop> {
    let lang = lang_of(&a)?;
    // R48-3: refused before anything is sent.
    if !a.yes && !p.is_interactive() {
        return Err(Stop::Refused(NEEDS_ANSWER.into()));
    }
    let mut req = args([("question", json!(a.question))]);
    for (k, on) in [
        ("judgment", a.judgment),
        ("show_sent", a.show_sent),
        ("new_session", a.new_session),
        ("yes", a.yes),
    ] {
        if on {
            req.insert(k.into(), json!(true));
        }
    }
    if let Some(d) = &a.dataset {
        req.insert("dataset".into(), json!(d));
    }
    if let Some(n) = a.limit {
        req.insert("limit".into(), json!(n));
    }
    if let Some(l) = &a.lang {
        req.insert("lang".into(), json!(l));
    }
    let (id, mut step) = reply(call(t, "blind.ask", req, ASK_TIMEOUT)?)?;
    for _ in 0..MAX_STEPS {
        match handle(t, &a, lang, &id, &step, p)? {
            Next::Answer(ans) => step = answer(t, &id, ans)?,
            Next::Step(s) => step = s,
            Next::Done(code) => return Ok(code),
        }
    }
    Err(Stop::Unavailable(
        "the ask took too many steps; it was left unanswered".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_texts() {
        assert_eq!(
            found_line(Lang::En, 2, "customer", "Anna Berg"),
            "Found 2 customers named Anna Berg:"
        );
        assert_eq!(
            found_line(Lang::Da, 2, "kunder", "Anna Berg"),
            "Fandt 2 kunder med navnet Anna Berg:"
        );
        assert_eq!(
            did_you_mean_prompt(
                Lang::En,
                "customer",
                "Søren Østergåd",
                "Søren Østergård, København"
            ),
            "No customer named \"Søren Østergåd\". Did you mean Søren Østergård, København? (y/N) "
        );
        assert_eq!(
            did_you_mean_prompt(Lang::Da, "kunde", "X", "Y"),
            "Ingen kunde ved navn \"X\". Mente du Y? (j/N) "
        );
        assert_eq!(
            keep_name_prompt("Zed Quorra", "crm"),
            "\"Zed Quorra\" is not in crm. Send it as plain text to the planner? This needs a touch (blind:name). (y/N) "
        );
        assert_eq!(run_prompt(Lang::En), "Run it? (Y/n) ");
        assert_eq!(run_prompt(Lang::Da), "Kør den? (J/n) ");
        assert_eq!(which_prompt(Lang::Da), "Hvilken? ");
        assert_eq!(
            approve_hint("ab12"),
            "approve this method for reuse: saiife blind methods approve ab12"
        );
    }

    #[test]
    fn answers_and_plurals() {
        assert!(is_yes("y") && is_yes("YES") && is_yes("j") && is_yes("Ja"));
        assert!(!is_yes("") && !is_yes("n") && !is_yes("nej"));
        assert!(is_run("") && is_run("y") && is_run("J"));
        assert!(!is_run("n") && !is_run("no") && !is_run("nej"));
        assert_eq!(plural("customer"), "customers");
        assert_eq!(plural("company"), "companies");
        assert_eq!(plural("day"), "days");
        assert_eq!(plural("box"), "boxes");
    }

    #[test]
    fn daemon_lines_are_sanitized_one_by_one() {
        assert_eq!(lines("a\u{1b}[m\nb"), ["a\\x1b[m", "b"]);
    }

    #[test]
    fn a_script_answers_in_order() {
        let mut p = super::super::prompt::Script {
            answers: ["1".to_string(), "y".to_string()].into_iter().collect(),
            prompts: Vec::new(),
            interactive: true,
        };
        assert_eq!(p.line(which_prompt(Lang::En)).unwrap(), "1");
        assert_eq!(p.line(run_prompt(Lang::En)).unwrap(), "y");
        assert!(p.line("x").is_err());
        assert_eq!(p.prompts, ["Which one? ", "Run it? (Y/n) ", "x"]);
        assert!(p.is_interactive());
    }
}
