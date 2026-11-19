//! Plan 48 Task 2: the lines around a checked answer (R48-4, spec §5.2):
//! the method line (the preview in the past tense), the cap note and the
//! footer. Pure text; the daemon puts them in the `answer` step.

use crate::calc::CellValue;
use crate::schema::Lang;
use crate::template::format_int;

/// The verbs that start a phrase of [`crate::preview::preview`] and their
/// past tense (en: `summing` -> `summed`; da: `lægger` -> `lagde`).
const EN_PAST: &[(&str, &str)] = &[
    ("summing", "summed"),
    ("counting", "counted"),
    ("finding", "found"),
    ("running", "ran"),
    ("listing", "listed"),
    ("computing", "computed"),
    ("comparing", "compared"),
    ("keeping", "kept"),
    ("using", "used"),
];
const DA_PAST: &[(&str, &str)] = &[
    ("lægger", "lagde"),
    ("tæller", "talte"),
    ("finder", "fandt"),
    ("kører", "kørte"),
    ("viser", "viste"),
    ("beregner", "beregnede"),
    ("sammenligner", "sammenlignede"),
    ("beholder", "beholdt"),
];

/// `phrase` with its first word in the past tense when it is one of the
/// preview's verbs (after a leading `and ` / `og `); else unchanged.
fn past_phrase(phrase: &str, lang: Lang) -> String {
    let (and, table) = match lang {
        Lang::En => ("and ", EN_PAST),
        Lang::Da => ("og ", DA_PAST),
    };
    let (lead, rest) = match phrase.strip_prefix(and) {
        Some(r) => (and, r),
        None => ("", phrase),
    };
    let (word, tail) = match rest.find(' ') {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    match table.iter().find(|(now, _)| *now == word) {
        Some((_, past)) => format!("{lead}{past}{tail}"),
        None => phrase.to_string(),
    }
}

/// The method line under an answer or a refusal after the run (R48-4):
/// `── method: <the preview, past tense>` (da `── metode: …`). `preview`
/// is the text [`crate::preview::preview`] made (`I'm summing …` /
/// `Jeg lægger …`): the opening pronoun and the final full stop go, and
/// each phrase's verb turns past (`summed …, and compared it with …`).
pub fn method_line(preview: &str, lang: Lang) -> String {
    let (head, opening) = match lang {
        Lang::En => ("── method: ", "I'm "),
        Lang::Da => ("── metode: ", "Jeg "),
    };
    let body = preview.strip_prefix(opening).unwrap_or(preview);
    let body = body.strip_suffix('.').unwrap_or(body);
    let past: Vec<String> = body.split(", ").map(|p| past_phrase(p, lang)).collect();
    format!("{head}{}", past.join(", "))
}

/// `n` grouped the answer's way (en `2,314`, da `2.314`).
fn grouped(n: u64, lang: Lang) -> String {
    let v = CellValue::Int(i64::try_from(n).unwrap_or(i64::MAX));
    format_int(&v, lang).map_or_else(|| n.to_string(), |(t, _)| t)
}

/// The cap note above the method line of a cut list (R48-4): en `showing
/// 100 of 2,314`, da `viser 100 af 2.314`.
pub fn cap_note(shown: u64, total: u64, lang: Lang) -> String {
    let (s, t) = (grouped(shown, lang), grouped(total, lang));
    match lang {
        Lang::En => format!("showing {s} of {t}"),
        Lang::Da => format!("viser {s} af {t}"),
    }
}

/// The footer (R48-4): en `── exact · method <id> (approved) | new method ·
/// <p> personal values sent · <n>/<n> numbers checked`, da `── præcis ·
/// metode <id> (godkendt) | ny metode · <p> personlige værdier sendt ·
/// <n>/<n> tal tjekket`. `approved` is the reused method's id; `numbers`
/// the checker's count (every number had a source, or the answer was
/// refused).
pub fn footer(
    approved: Option<&str>,
    personal_values: usize,
    numbers: usize,
    lang: Lang,
) -> String {
    match (lang, approved) {
        (Lang::En, Some(id)) => format!(
            "── exact · method {id} (approved) · {personal_values} personal values sent · \
             {numbers}/{numbers} numbers checked"
        ),
        (Lang::En, None) => format!(
            "── exact · new method · {personal_values} personal values sent · \
             {numbers}/{numbers} numbers checked"
        ),
        (Lang::Da, Some(id)) => format!(
            "── præcis · metode {id} (godkendt) · {personal_values} personlige værdier sendt · \
             {numbers}/{numbers} tal tjekket"
        ),
        (Lang::Da, None) => format!(
            "── præcis · ny metode · {personal_values} personlige værdier sendt · \
             {numbers}/{numbers} tal tjekket"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_line_is_past_tense() {
        assert_eq!(
            method_line(
                "I'm summing all invoices (amount) for Anna Berg, Aarhus, and comparing it \
                 with customers.credit_limit.",
                Lang::En
            ),
            "── method: summed all invoices (amount) for Anna Berg, Aarhus, and compared it \
             with customers.credit_limit"
        );
        assert_eq!(
            method_line(
                "I'm counting invoices, and finding the highest x in t.",
                Lang::En
            ),
            "── method: counted invoices, and found the highest x in t"
        );
        assert_eq!(
            method_line(
                "Jeg lægger alle invoices (amount) sammen for Anna Berg, og sammenligner med \
                 customers.credit_limit.",
                Lang::Da
            ),
            "── metode: lagde alle invoices (amount) sammen for Anna Berg, og sammenlignede \
             med customers.credit_limit"
        );
        // A user's word after a comma is not a verb of the table: unchanged.
        assert_eq!(
            method_line("I'm counting invoices for Bo, Listings.", Lang::En),
            "── method: counted invoices for Bo, Listings"
        );
    }

    #[test]
    fn cap_note_and_footer() {
        assert_eq!(cap_note(100, 2314, Lang::En), "showing 100 of 2,314");
        assert_eq!(cap_note(100, 2314, Lang::Da), "viser 100 af 2.314");
        assert_eq!(
            footer(None, 0, 3, Lang::En),
            "── exact · new method · 0 personal values sent · 3/3 numbers checked"
        );
        assert_eq!(
            footer(Some("m-balance-v2"), 0, 3, Lang::En),
            "── exact · method m-balance-v2 (approved) · 0 personal values sent · 3/3 numbers \
             checked"
        );
        assert_eq!(
            footer(None, 0, 2, Lang::Da),
            "── præcis · ny metode · 0 personlige værdier sendt · 2/2 tal tjekket"
        );
        assert_eq!(
            footer(Some("m1"), 0, 2, Lang::Da),
            "── præcis · metode m1 (godkendt) · 0 personlige værdier sendt · 2/2 tal tjekket"
        );
    }
}
