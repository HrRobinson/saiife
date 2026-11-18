//! Plan 45 Task 5: the strict number checker (R45-10).

mod common;

use saiife_shield::calc::{CellValue, ResultSet};
use saiife_shield::checker::{check, check_text};
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
    check_text(f, q, lang).unwrap_err().reason
}

#[test]
fn spec_answer_passes() {
    for lang in [Lang::En, Lang::Da] {
        let f = spec_filled(lang);
        let r = check_text(&f, "how much does Anna Berg owe?", lang).unwrap();
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
    assert_eq!(check_text(&f, "total?", Lang::En).unwrap().from_calc, 1);
    // a printed span whose digits do not match its recorded values refuses
    let f = filled("Total 0.31 now.", &[("0.31", &["0.30"], &[], false)]);
    let why = refusal(&f, "total?", Lang::En);
    assert!(!why.contains("0.31"), "{why}");
    // fixed text equal to a slot-printed value is from calc
    let f = filled("Owes 5.00 of 5 invoices.", &[("5.00", &["5"], &[], false)]);
    let r = check_text(&f, "x?", Lang::En).unwrap();
    assert_eq!(r.from_calc, 2);
    // a number straddling a span boundary refuses
    let f = filled("Owes 1234 kr", &[("12", &["12"], &[], false)]);
    assert!(check_text(&f, "x?", Lang::En).is_err());
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
        let why = check_text(&f, "how much?", lang).unwrap_err().reason;
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
    assert!(check_text(&f, "q?", Lang::En).is_err());
}

#[test]
fn question_numbers_allowed() {
    let f = filled("Only invoices over 10,000 count.", &[]);
    let r = check_text(&f, "which invoices are over 10 000?", Lang::En).unwrap();
    assert_eq!(r.from_question, 1);
    assert_eq!(r.numbers, 1);
    let f = filled("Tre gange er nok.", &[]);
    assert!(check_text(&f, "hvad med tre fakturaer?", Lang::Da).is_ok());
}

#[test]
fn param_display_numbers_allowed() {
    let f = filled(
        "Anna Berg (customer #4411) is fine.",
        &[("Anna Berg (customer #4411)", &[], &[], true)],
    );
    let r = check_text(&f, "q?", Lang::En).unwrap();
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
    let r = check_text(&f, "q?", Lang::En).unwrap();
    assert_eq!(r.numbers, 1);
    assert_eq!(r.from_calc, 1);
    // fixed-text date not printed refuses
    let f = filled("Due 1 July 2026 here.", &[]);
    assert!(check_text(&f, "q?", Lang::En).is_err());
    // wrong printed date
    let f = filled(
        "Due 2 July 2026 here.",
        &[("2 July 2026", &[], &["2026-07-01"], false)],
    );
    assert!(check_text(&f, "q?", Lang::En).is_err());
    // a date written in the question is allowed
    let f = filled("Since 1 July 2026.", &[]);
    let r = check_text(&f, "what changed since 1 July 2026?", Lang::En).unwrap();
    assert_eq!(r.from_question, 1);
    // Danish
    let f = filled("Siden 1. juli 2026.", &[]);
    assert!(check_text(&f, "hvad er sket siden 1. juli 2026?", Lang::Da).is_ok());
    assert!(check_text(&f, "hvad er sket?", Lang::Da).is_err());
    // a range form must equal a range in the question, not a printed day
    let f = filled(
        "In Q3 2026 only.",
        &[("Q3 2026", &[], &["2026-07-01"], false)],
    );
    assert!(check_text(&f, "q?", Lang::En).is_err());
    let f = filled("In Q3 2026 only.", &[]);
    assert!(check_text(&f, "q?", Lang::En).is_err());
    // round 2 (R2/R5): `Q3` is glued to its digit, so even a question-sourced
    // quarter is outside the fixed-text grammar; the planner writes plainer text
    assert!(check_text(&f, "what about Q3 2026?", Lang::En).is_err());
    let f = filled("In 1 July 2026 only.", &[]);
    assert!(check_text(&f, "what about Q3 2026?", Lang::En).is_err());
}

#[test]
fn articles_not_numbers() {
    let f = filled("It is a fine result, and en god one-off.", &[]);
    // "a", "en" are not numbers; "one" is
    let why = refusal(&f, "q?", Lang::En);
    assert!(why.contains("not from the calculator"), "{why}");
    let f = filled("It is a fine result.", &[]);
    assert_eq!(check_text(&f, "q?", Lang::En).unwrap().numbers, 0);
    let f = filled("Der er en kunde og et svar.", &[]);
    assert_eq!(check_text(&f, "q?", Lang::Da).unwrap().numbers, 0);
    let f = filled("Only one customer.", &[]);
    assert!(check_text(&f, "q?", Lang::En).is_err());
    assert!(check_text(&f, "show one customer", Lang::En).is_ok());
    let f = filled("Kun én kunde.", &[]);
    assert!(check_text(&f, "q?", Lang::Da).is_err());
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
            let _ = check_text(&f, &q, lang);
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
    assert!(check_text(&f, "q?", Lang::En).is_err());
}

// ---- fix round 1 ----

fn money_filled(v: f64) -> Filled {
    let cols = vec!["x".to_string()];
    let rs = ResultSet {
        columns: cols.clone(),
        rows: vec![vec![CellValue::Real(v)]],
        truncated: false,
        total_rows: None,
        ms: 0,
        row_band: "1".into(),
    };
    let t = parse_template("Balance is {money(x)}.", &cols, &[], 100).unwrap();
    fill(&t, &rs, &[], Lang::En).unwrap()
}

#[test]
fn unreadable_numerics_refused() {
    for bad in [
        "\u{b2}",
        "\u{ff15}",
        "\u{bd}",
        "\u{663}",
        "\u{216b}",
        "\u{661}\u{662}",
    ] {
        let text = format!("Total {bad} units.");
        let f = filled(&text, &[]);
        for lang in [Lang::En, Lang::Da] {
            let why = refusal(&f, "q?", lang);
            // a foldable numeral (`²`, `５`) is a number and may be quoted from
            // fixed text; an unreadable one never is
            if ["\u{bd}", "\u{663}", "\u{216b}", "\u{661}\u{662}"].contains(&bad) {
                assert!(!why.contains(bad), "{bad}: {why}");
            }
        }
        // even beside a calculated number
        let text = format!("It is 7 and {bad}.");
        let f = filled(&text, &[("7", &["7"], &[], false)]);
        assert!(check_text(&f, "q?", Lang::En).is_err(), "{bad}");
        // inside a printed data span
        let text = format!("- Bob {bad} Ltd");
        let f = filled(&text, &[(&format!("Bob {bad} Ltd"), &[], &[], false)]);
        assert!(check_text(&f, "q?", Lang::En).is_err(), "{bad}");
        // a question's unreadable numeral is never a source
        let f = filled(&format!("Only {bad}."), &[]);
        assert!(check_text(&f, &format!("what is {bad}?"), Lang::En).is_err());
    }
    // inside a parameter display it is a param source
    let f = filled(
        "Acme \u{216b} is fine.",
        &[("Acme \u{216b}", &[], &[], true)],
    );
    assert!(check_text(&f, "q?", Lang::En).is_ok());
}

#[test]
fn parser_trouble_in_the_answer_refuses() {
    for (text, lang) in [
        ("Over 10,000 only.", Lang::En),
        ("Over 10.000 only.", Lang::Da),
        ("Value 10,0,0 here.", Lang::En),
        ("About 2x more.", Lang::En),
        ("A 15kg box.", Lang::En),
        ("A B2B deal.", Lang::En),
        ("Due 1 July 2026; all of July 2026 x\u{b2}. n=2", Lang::En),
        ("I 1.3. kvartal 2026 var det.", Lang::Da),
        ("In 31 February 2026.", Lang::En),
    ] {
        let f = filled(text, &[]);
        assert!(check_text(&f, "how much?", lang).is_err(), "{text}");
    }
    // a normal answer whose numbers all come from the calculator passes
    let f = filled(
        "It is 12 of 40.",
        &[("12", &["12"], &[], false), ("40", &["40"], &[], false)],
    );
    assert!(check_text(&f, "q?", Lang::En).is_ok());
    assert!(check_text(&spec_filled(Lang::Da), "q?", Lang::Da).is_ok());
}

#[test]
fn sign_flip_refused() {
    for sign in ["-", "\u{2212}", "+"] {
        let text = format!("Balance is {sign}18,420.00 now.");
        let f = filled(&text, &[("18,420.00", &["18420.00"], &[], false)]);
        assert!(check_text(&f, "q?", Lang::En).is_err(), "{sign}");
    }
    // a printed negative passes
    let f = money_filled(-18420.0);
    assert_eq!(f.text, "Balance is -18,420.00.");
    let r = check_text(&f, "q?", Lang::En).unwrap();
    assert_eq!((r.numbers, r.from_calc), (1, 1));
    // a printed positive is not a negative
    let f = filled("Balance is -5.", &[("5", &["5"], &[], false)]);
    assert!(check_text(&f, "q?", Lang::En).is_err());
    // question signs
    let f = filled("It fell by -5 points.", &[]);
    // round 2 (R1/R2): a glued sign never passes, even when the question has it
    assert!(check_text(&f, "did it fall -5?", Lang::En).is_err());
    assert!(check_text(&f, "did it fall 5?", Lang::En).is_err());
    // a hyphen after a word is not a sign
    let f = filled("Item A-5 ok.", &[("5", &["5"], &[], false)]);
    let _ = check_text(&f, "q?", Lang::En);
}

#[test]
fn quantity_words_refused() {
    let en = [
        "twice",
        "thrice",
        "double",
        "triple",
        "half",
        "couple",
        "pair",
        "hundreds",
        "thousands",
        "millions",
        "billions",
        "trillion",
        "trillions",
        "dozens",
        "thirteenth",
        "nineteenth",
        "twentieth",
        "ninetieth",
        "hundredth",
        "thousandth",
        "millionth",
        "Twice",
    ];
    let da = [
        "halvanden",
        "halv",
        "halvt",
        "halve",
        "dobbelt",
        "dobbelte",
        "tredobbelt",
        "par",
        "hundreder",
        "tusinder",
        "millioner",
        "trettende",
        "fjortende",
        "nittende",
        "tyvende",
    ];
    for (words, lang) in [(&en[..], Lang::En), (&da[..], Lang::Da)] {
        for w in words {
            let text = format!("It was {w} as much.");
            let f = filled(&text, &[]);
            let why = refusal(&f, "how much?", lang);
            assert!(why.contains(*w), "{w}: {why}");
            // the same word in the question is a source
            assert!(check_text(&f, &format!("is it {w}?"), lang).is_ok(), "{w}");
            // inside a printed span the word is not quoted
            let f = filled(&text, &[(&format!("{w} as"), &[], &[], false)]);
            let why = refusal(&f, "how much?", lang);
            assert!(!why.contains(*w), "{w}: {why}");
            // inside a parameter display it is fine
            let f = filled(&text, &[(&format!("{w} as"), &[], &[], true)]);
            assert!(check_text(&f, "q?", lang).is_ok(), "{w}");
        }
    }
    // ordinary words stay fine
    let f = filled("The pairing and halfway house are ordinary.", &[]);
    assert!(check_text(&f, "q?", Lang::En).is_ok());
}

// ---- fix round 2: the fixed text is an allow-listed grammar (R1-R7) ----

use saiife_shield::sql::ErrorClass;

fn grammar_cols() -> Vec<String> {
    ["x", "a", "b", "owed", "limit"].map(String::from).to_vec()
}

fn parse_err(tpl: &str) -> bool {
    matches!(
        parse_template(tpl, &grammar_cols(), &[p1()], 100),
        Err(e) if e.class == ErrorClass::TemplateSlot
    )
}

/// The slot-printed span texts mark the numeric slots of `text`.
fn both_refuse(tpl: &str, text: &str, spans: &[&str], lang: Lang) {
    assert!(parse_err(tpl), "parse_template accepted {tpl:?}");
    let sp: Vec<(&str, &[&str], &[&str], bool)> = spans
        .iter()
        .map(|s| (*s, &["1"][..], &[][..], false))
        .collect();
    let f = filled(text, &sp);
    assert!(
        check_text(&f, "q?", lang).is_err(),
        "check accepted {text:?}"
    );
}

#[test]
fn grammar_refuses_sign_and_dash_lookalikes() {
    let signs = [
        "\u{b1}",
        "\u{2010}",
        "\u{2011}",
        "\u{2012}",
        "\u{2013}",
        "\u{2014}",
        "\u{fe63}",
        "\u{ff0d}",
        "\u{2796}",
        "\u{2212}",
        "-\u{2060}",
        "-\u{200b}",
        "- ",
        "+",
        "-",
        "~",
    ];
    for g in signs {
        let tpl = format!("Balance is {g}{{money(x)}} now.");
        let text = format!("Balance is {g}18,420.00 now.");
        both_refuse(&tpl, &text, &["18,420.00"], Lang::En);
    }
    both_refuse(
        "It is ({money(x)}) now.",
        "It is (18,420.00) now.",
        &["18,420.00"],
        Lang::En,
    );
    both_refuse(
        "It is '{money(x)}' now.",
        "It is '18,420.00' now.",
        &["18,420.00"],
        Lang::En,
    );
    both_refuse(
        "It is {money(x)}/yr now.",
        "It is 18,420.00/yr now.",
        &["18,420.00"],
        Lang::En,
    );
}

#[test]
fn grammar_refuses_scale_words_and_glue() {
    for w in [
        "mio.", "bn", "k", "m", "thousand", "million", "billion", "x", "e", "gange", "times",
        "percent", "procent", "pct", "tusind", "mrd", "lakh", "Hundred",
    ] {
        let tpl = format!("It is {{money(x)}} {w} now.");
        let text = format!("It is 18,420.00 {w} now.");
        both_refuse(&tpl, &text, &["18,420.00"], Lang::En);
        let tpl = format!("It is {w} {{money(x)}} now.");
        let text = format!("It is {w} 18,420.00 now.");
        both_refuse(&tpl, &text, &["18,420.00"], Lang::En);
    }
    for glued in ["thousand", "e3", "k", "x"] {
        let tpl = format!("It is {{money(x)}}{glued} now.");
        let text = format!("It is 18,420.00{glued} now.");
        both_refuse(&tpl, &text, &["18,420.00"], Lang::En);
    }
    both_refuse("A{int(x)} b", "A18 b", &["18"], Lang::En);
}

#[test]
fn grammar_refuses_compound_scale_words() {
    // Plan 45 final review M6: also in the checker's re-check of the filled
    // text.
    for w in ["hundredthousand", "tenmillion", "halvmilliard", "totusinde"] {
        let tpl = format!("It is {{money(x)}} {w} now.");
        let text = format!("It is 18,420.00 {w} now.");
        both_refuse(&tpl, &text, &["18,420.00"], Lang::En);
        let tpl = format!("It is {w} {{money(x)}} now.");
        let text = format!("It is {w} 18,420.00 now.");
        both_refuse(&tpl, &text, &["18,420.00"], Lang::En);
    }
}

#[test]
fn grammar_refuses_joined_slots() {
    both_refuse(
        "{int(a)}\u{200b}{int(b)}",
        "1\u{200b}2",
        &["1", "2"],
        Lang::En,
    );
    both_refuse("{int(a)}{int(b)}", "12", &["1", "2"], Lang::En);
    both_refuse("{int(a)} {int(b)}", "1 2", &["1", "2"], Lang::En);
    both_refuse("{int(a)}, {int(b)}", "1, 2", &["1", "2"], Lang::En);
    both_refuse("{int(a)} - {int(b)}", "1 - 2", &["1", "2"], Lang::En);
    both_refuse("{int(a)}\u{a0}{int(b)}", "1\u{a0}2", &["1", "2"], Lang::En);
    both_refuse(
        "{int(a)}\u{202f}{int(b)}",
        "1\u{202f}2",
        &["1", "2"],
        Lang::En,
    );
}

#[test]
fn grammar_refuses_lookalike_and_foreign_words() {
    for w in [
        "\u{ff54}\u{ff48}\u{ff52}\u{ff45}\u{ff45}",
        "t\u{4bb}ree",
        "\u{1d42d}\u{1d421}\u{1d42b}\u{1d41e}\u{1d41e}",
        "\u{4e09}",
        "\u{5341}",
        "\u{3007}",
        "caf\u{e8}",
        "na\u{ef}ve",
        "\u{20ac}",
        "\u{a3}",
        "%",
        "#",
        "{{",
    ] {
        let tpl = format!("It was {w} times.");
        assert!(parse_err(&tpl), "{w}");
        let f = filled(&format!("It was {w} times."), &[]);
        assert!(check_text(&f, "it was it", Lang::En).is_err(), "{w}");
    }
    // English number words in a Danish answer
    for w in ["three", "ten", "twenty-one", "hundred"] {
        let f = filled(&format!("Det er {w} fakturaer."), &[]);
        assert!(check_text(&f, "hvor mange?", Lang::Da).is_err(), "{w}");
    }
}

#[test]
fn grammar_refuses_roman_numerals() {
    for t in [
        "In Q III only.",
        "Year MMXXVI only.",
        "In QIII only.",
        "Part II of it.",
        "(IV) here.",
    ] {
        assert!(parse_err(t), "{t}");
        let f = filled(t, &[]);
        assert!(check_text(&f, "q?", Lang::En).is_err(), "{t}");
    }
    let f = filled("I think so.", &[]);
    assert!(check_text(&f, "q?", Lang::En).is_ok());
}

#[test]
fn more_quantity_words_refused() {
    for w in [
        "nil",
        "nought",
        "naught",
        "once",
        "quarter",
        "single",
        "both",
        "score",
        "gross",
        "thirds",
        "halves",
        "twofold",
        "tenfold",
        "quadruple",
        "dusin",
        "snes",
        "kvart",
        "halvdelen",
        "billion",
        "billioner",
        "ninefold",
        "septillionth",
        "femogtredivte",
        "firedobbelt",
        "kvartdel",
        "stykvis",
    ] {
        let f = filled(&format!("It was {w} as much."), &[]);
        let why = refusal(&f, "how much?", Lang::En);
        assert!(why.contains(w), "{w}: {why}");
        assert!(
            check_text(&f, &format!("is it {w}?"), Lang::En).is_ok(),
            "{w}"
        );
    }
}

#[test]
fn grammar_still_passes_the_good_cases() {
    for lang in [Lang::En, Lang::Da] {
        assert!(check_text(&spec_filled(lang), "q?", lang).is_ok());
    }
    assert!(!parse_err("Anna owes {money(x)}, and {int(a)} more."));
    assert!(!parse_err("From {int(a)} to {int(b)} items."));
    assert!(!parse_err("Owes {money(x)}.\n{int(a)} invoices!"));
    let f = filled(
        "From 3 to 7 items.",
        &[("3", &["3"], &[], false), ("7", &["7"], &[], false)],
    );
    assert!(check_text(&f, "q?", Lang::En).is_ok());
    assert!(check_text(&money_filled(-18420.0), "q?", Lang::En).is_ok());
    let f = filled("Kunden skylder 7 kr. i alt.", &[("7", &["7"], &[], false)]);
    assert!(check_text(&f, "q?", Lang::Da).is_ok());
    let f = filled(
        "Har du \u{e6}\u{f8}\u{e5} \u{c6}\u{d8}\u{c5} caf\u{e9}?",
        &[],
    );
    assert!(check_text(&f, "q?", Lang::Da).is_ok());
}

// R5: digits in fixed text are delimited like a numeric slot, and need the
// question as their source. Plan 44 carry M1: phone numbers, amounts and ids
// in a template's fixed text are covered by the same rules.
#[test]
fn fixed_digits_are_delimited_and_sourced() {
    // glued or signed: refused at parse and at check even with the question
    for (tpl, q) in [
        ("Over 10,000kr only.", "over 10,000kr?"),
        ("Over (10,000) only.", "over 10,000?"),
        ("Over -10,000 only.", "over -10,000?"),
        ("Part B2B only.", "b2b 2?"),
        ("Over 10,000 mio. only.", "over 10,000?"),
        ("Over 10,000 x 3 only.", "over 10,000 3?"),
        ("Over 10 000 only.", "over 10 000?"),
        ("Call 12 34 56 78 now.", "call 12 34 56 78?"),
        ("Call 4411-2200 now.", "call 4411?"),
    ] {
        assert!(parse_err(tpl), "parse accepted {tpl:?}");
        let f = filled(tpl, &[]);
        assert!(
            check_text(&f, q, Lang::En).is_err(),
            "check accepted {tpl:?}"
        );
    }
    // delimited and in the question: passes both
    for (tpl, q, lang) in [
        ("Only invoices over 10,000 count.", "over 10 000?", Lang::En),
        ("Kun over 10.000 tæller.", "over 10.000?", Lang::Da),
        ("Between 3 and 7 items.", "from 3 to 7?", Lang::En),
    ] {
        assert!(!parse_err(tpl), "parse refused {tpl:?}");
        let f = filled(tpl, &[]);
        assert!(check_text(&f, q, lang).is_ok(), "check refused {tpl:?}");
    }
    // delimited but not in the question: parse cannot know, check refuses
    for tpl in ["Call 4411 now.", "Pay 1,500.00 now.", "Phone 555 now."] {
        assert!(!parse_err(tpl), "{tpl}");
        let f = filled(tpl, &[]);
        assert!(check_text(&f, "q?", Lang::En).is_err(), "{tpl}");
    }
}

// R7 [call: controller, 2026-11-17]: the grammar is small on purpose; a claim
// with no number in it is the business of the method preview, the answer's
// method line and approved methods, not of the checker.
#[test]
fn semantic_claims_without_numbers_are_not_the_checkers_job() {
    let f = filled("Anna Berg owes nothing.", &[]);
    assert!(check_text(&f, "what does Anna Berg owe?", Lang::En).is_ok());
    assert!(!parse_err("Anna Berg owes nothing."));
}

// ---- fix round 3 ----

#[test]
fn roman_numerals_with_punctuation_or_lower_case_refused() {
    for t in [
        "In Q-III Anna owed it.",
        "In Q.III only.",
        "Parts II/III only.",
        "Parts XI-XII only.",
        "In MMXXVI's year.",
        "In xii only.",
        "Part iv only.",
        "Year mcm only.",
    ] {
        assert!(parse_err(t), "parse accepted {t:?}");
        let f = filled(t, &[]);
        assert!(
            check_text(&f, "q?", Lang::En).is_err(),
            "check accepted {t:?}"
        );
    }
    let f = filled("In Q-III Anna owed 5.", &[("5", &["5"], &[], false)]);
    assert!(check_text(&f, "q?", Lang::En).is_err());
    for t in [
        "I think so.",
        "Kunden er i byen.",
        "A mix of civil and vivid, mild things.",
        "Please id the lid.",
    ] {
        assert!(!parse_err(t), "parse refused {t:?}");
        let f = filled(t, &[]);
        assert!(
            check_text(&f, "q?", Lang::En).is_ok(),
            "check refused {t:?}"
        );
    }
}

#[test]
fn number_words_of_both_languages_refused_on_every_answer() {
    for t in ["It cost fem tusind.", "Det var tre.", "A million kr."] {
        let f = filled(t, &[]);
        assert!(check_text(&f, "q?", Lang::En).is_err(), "{t}");
    }
    // everyday English words that are Danish numbers are exempt on English
    let f = filled("Sent to Anna on fire day, en et.", &[]);
    assert!(check_text(&f, "q?", Lang::En).is_ok());
    // but the English lexicon still applies to Danish answers
    let f = filled("Det var three fakturaer.", &[]);
    assert!(check_text(&f, "q?", Lang::Da).is_err());
    // and a question that has the word licenses it
    let f = filled("It cost fem tusind.", &[]);
    assert!(check_text(&f, "hvad med fem tusind?", Lang::En).is_ok());
}

#[test]
fn param_and_cmp_slots_are_judged_like_numbers_for_neighbours() {
    for tpl in [
        "{param(p1)} million owed.",
        "About {param(p1)}k owed.",
        "About {param(p1)}, mio. owed.",
        "Is {cmp(a, b)}x it.",
        "Over {cmp(a, b)}% it.",
    ] {
        assert!(parse_err(tpl), "{tpl}");
    }
    // check side: a param display glued to a scale word
    let f = filled(
        "Anna Berg (customer #4411) million owed.",
        &[("Anna Berg (customer #4411)", &[], &[], true)],
    );
    assert!(check_text(&f, "q?", Lang::En).is_err());
    let f = filled(
        "About Anna Berg (customer #4411)k owed.",
        &[("Anna Berg (customer #4411)", &[], &[], true)],
    );
    assert!(check_text(&f, "q?", Lang::En).is_err());
    assert!(!parse_err("More than {param(p1)} invoices."));
    assert!(!parse_err("{param(p1)} owes {int(a)} invoices."));
    assert!(!parse_err("It is {cmp(a, b)} her limit."));
}

// ---- fix round 4 ----

#[test]
fn q_then_a_single_roman_letter_refused() {
    for t in [
        "In Q-I Anna owed it.",
        "In Q.I Anna owed it.",
        "In Q/I Anna owed it.",
        "In Q-V Anna owed it.",
        "In Q I Anna owed it.",
        "In Q III Anna owed it.",
        "In q iv Anna owed it.",
    ] {
        assert!(parse_err(t), "parse accepted {t:?}");
        let f = filled(t, &[]);
        assert!(
            check_text(&f, "q?", Lang::En).is_err(),
            "check accepted {t:?}"
        );
    }
    for tpl in [
        "In Q-I Anna owed {money(x)}.",
        "In Q I Anna owed {money(x)}.",
    ] {
        assert!(parse_err(tpl), "parse accepted {tpl:?}");
    }
    let f = filled("In Q-I Anna owed 5.", &[("5", &["5"], &[], false)]);
    assert!(check_text(&f, "q?", Lang::En).is_err());
    for t in [
        "I think so, and I owe it.",
        "Kunden er i byen.",
        "Kunden bor i Aarhus, i Danmark.",
    ] {
        assert!(!parse_err(t), "parse refused {t:?}");
        let f = filled(t, &[]);
        assert!(
            check_text(&f, "q?", Lang::En).is_ok(),
            "check refused {t:?}"
        );
    }
}

#[test]
fn mil_and_mill_are_scale_words() {
    assert!(parse_err("Anna owes {int(a)} mill. kr."));
    assert!(parse_err("Anna owes {money(x)} mil"));
    let f = filled("Anna owes 5 mill. kr.", &[("5", &["5"], &[], false)]);
    assert!(check_text(&f, "q?", Lang::En).is_err());
    let f = filled("Anna owes 5 mil", &[("5", &["5"], &[], false)]);
    assert!(check_text(&f, "q?", Lang::En).is_err());
    let f = filled("It was a mill kr.", &[]);
    assert!(check_text(&f, "q?", Lang::En).is_err());
}

/// Ruling F-f (plan 45 final review part 2): the checker's entry point
/// refuses an answer whose method does not apply a bound filter of the
/// question, even when the template shows it.
fn total_rs(total: f64, limit: f64) -> ResultSet {
    ResultSet {
        columns: vec!["total".into(), "credit_limit".into()],
        rows: vec![vec![CellValue::Real(total), CellValue::Real(limit)]],
        truncated: false,
        total_rows: None,
        ms: 0,
        row_band: "1-9".into(),
    }
}

fn q3() -> Param {
    Param {
        name: "p2".into(),
        ty: ParamType::DateRange,
        bound: Some(Bound::DateRange("2026-07-01".into(), "2026-10-01".into())),
        display: "Q3 2026".into(),
    }
}

const ALL_TIME: &str = "SELECT SUM(i.amount) AS total, c.credit_limit FROM invoices i \
    JOIN customers c ON c.id = i.customer_id WHERE c.id = :p1";

#[test]
fn check_refuses_a_shown_filter_the_method_ignores() {
    let ps = vec![common::entity(1), q3()];
    let cols: Vec<String> = vec!["total".into(), "credit_limit".into()];
    let tpl = parse_template(
        "{param(p1)} owes {money(total)} in {param(p2)}.",
        &cols,
        &ps,
        100,
    )
    .unwrap();
    let f = fill(&tpl, &total_rs(412.0, 5000.0), &ps, Lang::En).unwrap();
    let q = "What does Anna Berg owe in Q3 2026?";
    // The method lacks the date filter: refused although the text is clean.
    let all_time = common::v(ALL_TIME, &ps);
    check_text(&f, q, Lang::En).unwrap();
    let r = check(&all_time, &tpl, &ps, &f, q, Lang::En).unwrap_err();
    assert_eq!(r.class, ErrorClass::ParamMisuse);
    // With the filter it passes.
    let in_q3 = common::v(
        &format!("{ALL_TIME} AND i.issued >= :p2_from AND i.issued < :p2_to"),
        &ps,
    );
    check(&in_q3, &tpl, &ps, &f, q, Lang::En).unwrap();
}

#[test]
fn check_refuses_a_shown_entity_the_method_ignores() {
    // A method over every customer (validated against a draft without the
    // entity) with an answer that names Anna Berg.
    let ps = vec![common::entity(1)];
    let everyone = common::v("SELECT SUM(i.amount) AS total FROM invoices i", &[]);
    let cols: Vec<String> = vec!["total".into()];
    let tpl = parse_template("{param(p1)} owes {money(total)}.", &cols, &ps, 100).unwrap();
    let rs = ResultSet {
        columns: cols.clone(),
        rows: vec![vec![CellValue::Real(412.0)]],
        truncated: false,
        total_rows: None,
        ms: 0,
        row_band: "1-9".into(),
    };
    let f = fill(&tpl, &rs, &ps, Lang::En).unwrap();
    let r = check(&everyone, &tpl, &ps, &f, "What does Anna owe?", Lang::En).unwrap_err();
    assert_eq!(r.class, ErrorClass::ParamMisuse);
}

#[test]
fn check_passes_a_stated_threshold_with_a_cmp() {
    let limit = Param {
        name: "p2".into(),
        ty: ParamType::Amount,
        bound: Some(Bound::Amount(dec("10000"))),
        display: "10,000.00".into(),
    };
    let ps = vec![common::entity(1), limit];
    let method = common::v(ALL_TIME, &ps);
    let cols: Vec<String> = vec!["total".into(), "credit_limit".into()];
    let tpl = parse_template(
        "Is {param(p1)} over {param(p2)}? She owes {money(total)}, \
         {cmp(total, credit_limit)} her limit of {money(credit_limit)}.",
        &cols,
        &ps,
        100,
    )
    .unwrap();
    let f = fill(&tpl, &total_rs(600.0, 5000.0), &ps, Lang::En).unwrap();
    let rep = check(
        &method,
        &tpl,
        &ps,
        &f,
        "Is Anna Berg over 10,000?",
        Lang::En,
    )
    .unwrap();
    assert_eq!(rep.from_calc, 2);
}
