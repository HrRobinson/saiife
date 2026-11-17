//! Plan 45 Task 5: the strict number checker (R45-10).

use saiife_shield::calc::{CellValue, ResultSet};
use saiife_shield::checker::check;
use saiife_shield::schema::{Bound, Decimal, Lang, Param, ParamType};
use saiife_shield::template::{fill, parse_template, Filled, Printed};

fn dec(s: &str) -> Decimal {
    Decimal::parse_plain(s).unwrap()
}

fn p1() -> Param {
    Param {
        name: "p1".into(),
        ty: ParamType::Entity {
            table: "customers".into(),
            word: "customer".into(),
        },
        bound: Some(Bound::Keys(vec![4411])),
        display: "Anna Berg (customer #4411)".into(),
    }
}

fn spec_filled(lang: Lang) -> Filled {
    let cols: Vec<String> = ["owed", "n", "credit_limit"].map(String::from).to_vec();
    let rs = ResultSet {
        columns: cols.clone(),
        rows: vec![vec![
            CellValue::Real(18420.0),
            CellValue::Int(3),
            CellValue::Int(15000),
        ]],
        truncated: false,
        total_rows: None,
        ms: 0,
        row_band: "1-9".into(),
    };
    let t = parse_template(
        "{param(p1)} owes {money(owed, NOK)} across {int(n)} open invoices. \
That is {cmp(owed, credit_limit)} her limit of {money(credit_limit, NOK)}.",
        &cols,
        &[p1()],
        100,
    )
    .unwrap();
    fill(&t, &rs, &[p1()], lang).unwrap()
}

/// Fixed text with printed spans located by substring.
fn filled(text: &str, spans: &[(&str, &[&str], &[&str], bool)]) -> Filled {
    let printed = spans
        .iter()
        .map(|(s, vals, dates, fp)| {
            let start = text.find(s).unwrap();
            Printed {
                start,
                end: start + s.len(),
                values: vals.iter().map(|v| dec(v)).collect(),
                dates: dates.iter().map(|d| d.to_string()).collect(),
                from_param: *fp,
            }
        })
        .collect();
    Filled {
        text: text.into(),
        printed,
    }
}

fn refusal(f: &Filled, q: &str, lang: Lang) -> String {
    check(f, q, lang).unwrap_err().reason
}

#[test]
fn spec_answer_passes() {
    for lang in [Lang::En, Lang::Da] {
        let f = spec_filled(lang);
        let r = check(&f, "how much does Anna Berg owe?", lang).unwrap();
        assert_eq!(r.from_calc, 3, "{}", f.text);
        assert_eq!(r.from_params, 1);
        assert_eq!(r.from_question, 0);
        assert_eq!(r.numbers, 4);
    }
}

#[test]
fn checker_uses_printed_values() {
    // 0.1 + 0.2 printed as 0.30; scale-insensitive equality.
    let f = filled("Total 0.30 now.", &[("0.30", &["0.3"], &[], false)]);
    assert_eq!(check(&f, "total?", Lang::En).unwrap().from_calc, 1);
    // a printed span whose digits do not match its recorded values refuses
    let f = filled("Total 0.31 now.", &[("0.31", &["0.30"], &[], false)]);
    let why = refusal(&f, "total?", Lang::En);
    assert!(!why.contains("0.31"), "{why}");
    // fixed text equal to a slot-printed value is from calc
    let f = filled("Owes 5.00 of 5 invoices.", &[("5.00", &["5"], &[], false)]);
    let r = check(&f, "x?", Lang::En).unwrap();
    assert_eq!(r.from_calc, 2);
    // a number straddling a span boundary refuses
    let f = filled("Owes 1234 kr", &[("12", &["12"], &[], false)]);
    assert!(check(&f, "x?", Lang::En).is_err());
}

#[test]
fn fixed_text_numbers_refused() {
    let cases = [
        ("Revenue in Q3 was ok.", Lang::En),
        ("It happened three times.", Lang::En),
        ("Det skete tre gange.", Lang::Da),
        ("Unpaid since 2025 only.", Lang::En),
        ("Growth was 15% overall.", Lang::En),
    ];
    for (text, lang) in cases {
        let f = filled(text, &[]);
        let why = check(&f, "how much?", lang).unwrap_err().reason;
        assert!(why.contains("not from the calculator"), "{text}: {why}");
    }
    // the reason quotes the offending number from fixed text
    let f = filled("Unpaid since 2025 only.", &[]);
    assert_eq!(
        refusal(&f, "q?", Lang::En),
        "the number 2025 is not from the calculator or your question"
    );
    // a printed percent is not enough for a different fixed percent
    let f = filled("Rate 4.5% vs 15%.", &[("4.5%", &["4.5"], &[], false)]);
    assert!(check(&f, "q?", Lang::En).is_err());
}

#[test]
fn question_numbers_allowed() {
    let f = filled("Only invoices over 10,000 count.", &[]);
    let r = check(&f, "which invoices are over 10 000?", Lang::En).unwrap();
    assert_eq!(r.from_question, 1);
    assert_eq!(r.numbers, 1);
    let f = filled("Tre gange er nok.", &[]);
    assert!(check(&f, "hvad med tre fakturaer?", Lang::Da).is_ok());
}

#[test]
fn param_display_numbers_allowed() {
    let f = filled(
        "Anna Berg (customer #4411) is fine.",
        &[("Anna Berg (customer #4411)", &[], &[], true)],
    );
    let r = check(&f, "q?", Lang::En).unwrap();
    assert_eq!((r.from_params, r.numbers), (1, 1));
}

#[test]
fn no_data_in_reason() {
    // digits in a list text cell (recorded as no value) refuse, unquoted
    let f = filled(
        "- Bob 9981 Ltd · 7",
        &[("Bob 9981 Ltd · 7", &["7"], &[], false)],
    );
    let why = refusal(&f, "q?", Lang::En);
    assert_eq!(why, "a number in the answer is not from the calculator");
    // an unsourced number inside a param span is a param source; but a
    // number straddling out of it refuses without quoting the display
    let f = filled("ab #4411 77", &[("#4411 7", &[], &[], true)]);
    let why = refusal(&f, "q?", Lang::En);
    assert!(!why.contains("4411"), "{why}");
}

#[test]
fn dates_checked() {
    // printed date ok
    let f = filled(
        "Due 1 July 2026 here.",
        &[("1 July 2026", &[], &["2026-07-01"], false)],
    );
    let r = check(&f, "q?", Lang::En).unwrap();
    assert_eq!(r.numbers, 1);
    assert_eq!(r.from_calc, 1);
    // fixed-text date not printed refuses
    let f = filled("Due 1 July 2026 here.", &[]);
    assert!(check(&f, "q?", Lang::En).is_err());
    // wrong printed date
    let f = filled(
        "Due 2 July 2026 here.",
        &[("2 July 2026", &[], &["2026-07-01"], false)],
    );
    assert!(check(&f, "q?", Lang::En).is_err());
    // a date written in the question is allowed
    let f = filled("Since 1 July 2026.", &[]);
    let r = check(&f, "what changed since 1 July 2026?", Lang::En).unwrap();
    assert_eq!(r.from_question, 1);
    // Danish
    let f = filled("Siden 1. juli 2026.", &[]);
    assert!(check(&f, "hvad er sket siden 1. juli 2026?", Lang::Da).is_ok());
    assert!(check(&f, "hvad er sket?", Lang::Da).is_err());
    // a range form must equal a range in the question, not a printed day
    let f = filled(
        "In Q3 2026 only.",
        &[("Q3 2026", &[], &["2026-07-01"], false)],
    );
    assert!(check(&f, "q?", Lang::En).is_err());
    let f = filled("In Q3 2026 only.", &[]);
    assert!(check(&f, "q?", Lang::En).is_err());
    assert!(check(&f, "what about Q3 2026?", Lang::En).is_ok());
    let f = filled("In 1 July 2026 only.", &[]);
    assert!(check(&f, "what about Q3 2026?", Lang::En).is_err());
}

#[test]
fn articles_not_numbers() {
    let f = filled("It is a fine result, and en god one-off.", &[]);
    // "a", "en" are not numbers; "one" is
    let why = refusal(&f, "q?", Lang::En);
    assert!(why.contains("not from the calculator"), "{why}");
    let f = filled("It is a fine result.", &[]);
    assert_eq!(check(&f, "q?", Lang::En).unwrap().numbers, 0);
    let f = filled("Der er en kunde og et svar.", &[]);
    assert_eq!(check(&f, "q?", Lang::Da).unwrap().numbers, 0);
    let f = filled("Only one customer.", &[]);
    assert!(check(&f, "q?", Lang::En).is_err());
    assert!(check(&f, "show one customer", Lang::En).is_ok());
    let f = filled("Kun én kunde.", &[]);
    assert!(check(&f, "q?", Lang::Da).is_err());
}

#[test]
fn never_panics_on_hostile_utf8() {
    let pieces = [
        "İ", "\u{212A}", "ß", "e\u{301}", "🙂", "1", "23", "4,5", "%", "Q3", " ", "juli", "2026",
        "one", "tre", "\u{661}", "10 000", "1.7.2026",
    ];
    let mut seed = 0x1234_5678_9ABC_DEF1u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..3000 {
        let mut text = String::new();
        for _ in 0..(next() % 10) {
            text.push_str(pieces[(next() % pieces.len() as u64) as usize]);
        }
        let mut q = String::new();
        for _ in 0..(next() % 6) {
            q.push_str(pieces[(next() % pieces.len() as u64) as usize]);
        }
        let n = text.len() as u64 + 4;
        let printed = (0..(next() % 4))
            .map(|_| Printed {
                start: (next() % n) as usize,
                end: (next() % n) as usize,
                values: vec![dec("1")],
                dates: vec!["2026-07-01".into()],
                from_param: next() % 2 == 0,
            })
            .collect();
        let f = Filled { text, printed };
        for lang in [Lang::En, Lang::Da] {
            let _ = check(&f, &q, lang);
        }
    }
    // an invalid span is a refusal
    let f = Filled {
        text: "İ 5".into(),
        printed: vec![Printed {
            start: 1,
            end: 99,
            values: vec![],
            dates: vec![],
            from_param: true,
        }],
    };
    assert!(check(&f, "q?", Lang::En).is_err());
}
