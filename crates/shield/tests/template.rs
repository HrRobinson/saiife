//! Plan 45 Task 4: answer templates and deterministic formatters.

mod common;

use saiife_shield::calc::{CellValue, ResultSet};
use saiife_shield::schema::{Bound, Decimal, Lang, Param, ParamType};
use saiife_shield::sql::ErrorClass;
use saiife_shield::template::{
    check_params_covered, fill, format_date, format_int, format_money, format_number,
    format_percent, format_ratio_percent, format_round, parse_template,
};

fn dec(s: &str) -> Decimal {
    Decimal::parse_plain(s).unwrap()
}

fn cols(c: &[&str]) -> Vec<String> {
    c.iter().map(|s| s.to_string()).collect()
}

fn rs(c: &[&str], rows: Vec<Vec<CellValue>>) -> ResultSet {
    ResultSet {
        columns: cols(c),
        rows,
        truncated: false,
        total_rows: None,
        ms: 0,
        row_band: "1-9".into(),
    }
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

const SPEC: &str = "{param(p1)} owes {money(owed, NOK)} across {int(n)} open invoices. \
That is {cmp(owed, credit_limit)} her limit of {money(credit_limit, NOK)}.";

fn spec_rs() -> ResultSet {
    rs(
        &["owed", "n", "credit_limit"],
        vec![vec![
            CellValue::Real(18420.0),
            CellValue::Int(3),
            CellValue::Int(15000),
        ]],
    )
}

fn parse(s: &str, c: &[&str]) -> saiife_shield::template::Template {
    parse_template(s, &cols(c), &[p1()], 100).unwrap()
}

fn class(s: &str, c: &[&str]) -> (ErrorClass, Option<String>) {
    let e = parse_template(s, &cols(c), &[p1()], 100).unwrap_err();
    (e.class, e.detail)
}

#[test]
fn spec_example_fill_en() {
    let t = parse(SPEC, &["owed", "n", "credit_limit"]);
    let f = fill(&t, &spec_rs(), &[p1()], Lang::En).unwrap();
    assert_eq!(
        f.text,
        "Anna Berg (customer #4411) owes 18,420.00 NOK across 3 open invoices. \
That is above her limit of 15,000.00 NOK."
    );
    assert!(f.printed[0].from_param && f.printed[0].values.is_empty());
    assert_eq!(
        &f.text[f.printed[0].start..f.printed[0].end],
        "Anna Berg (customer #4411)"
    );
    assert_eq!(f.printed[1].values, vec![dec("18420.00")]);
    assert_eq!(
        &f.text[f.printed[1].start..f.printed[1].end],
        "18,420.00 NOK"
    );
    assert_eq!(f.printed[2].values, vec![dec("3")]);
    assert!(f.printed[3].values.is_empty());
}

#[test]
fn spec_example_fill_da() {
    let t = parse(SPEC, &["owed", "n", "credit_limit"]);
    let f = fill(&t, &spec_rs(), &[p1()], Lang::Da).unwrap();
    assert!(f.text.contains("18.420,00 NOK"), "{}", f.text);
    assert!(f.text.contains("15.000,00 NOK"));
    assert!(f.text.contains(" over "));
}

#[test]
fn float_sum_prints_two_decimals() {
    let r = rs(&["x"], vec![vec![CellValue::Real(0.1 + 0.2)]]);
    let t = parse("{money(x)}", &["x"]);
    let f = fill(&t, &r, &[], Lang::En).unwrap();
    assert_eq!(f.text, "0.30");
    assert_eq!(f.printed[0].values, vec![dec("0.30")]);
    assert_eq!(
        format_money(&CellValue::Real(2.675), Lang::En).unwrap().0,
        "2.68"
    );
    assert_eq!(
        format_money(&CellValue::Real(0.125), Lang::En).unwrap().0,
        "0.12"
    );
}

#[test]
fn list_rows() {
    let r = rs(
        &["name", "owed"],
        vec![
            vec![CellValue::Text("A".into()), CellValue::Real(1234.5)],
            vec![CellValue::Text("B".into()), CellValue::Int(7)],
            vec![CellValue::Text("C".into()), CellValue::Real(0.0)],
        ],
    );
    let t = parse("{list(name, owed)}", &["name", "owed"]);
    let f = fill(&t, &r, &[], Lang::En).unwrap();
    assert_eq!(f.text, "- A · 1,234.50\n- B · 7\n- C · 0.00");
    assert_eq!(f.text.lines().count(), 3);
    assert_eq!(
        f.printed[0].values,
        vec![dec("1234.50"), dec("7"), dec("0.00")]
    );
}

#[test]
fn bad_slot_is_template_slot() {
    let c = &["x"];
    assert_eq!(
        class("{money(nope)}", c),
        (ErrorClass::TemplateSlot, Some("nope".into()))
    );
    assert_eq!(
        class("{frob(x)}", c),
        (ErrorClass::TemplateSlot, Some("frob".into()))
    );
    assert_eq!(
        class("{int(r200.x)}", c),
        (ErrorClass::TemplateSlot, Some("r200.x".into()))
    );
    assert_eq!(class("{round(x, 9)}", c).0, ErrorClass::TemplateSlot);
    assert_eq!(class("{param(p9)}", c).0, ErrorClass::TemplateSlot);
    assert_eq!(class("{money(x, nok)}", c).0, ErrorClass::TemplateSlot);
    assert_eq!(class("{int(x, x)}", c).0, ErrorClass::TemplateSlot);
    assert_eq!(class("{int(x)", c).0, ErrorClass::TemplateSlot);
    assert_eq!(class("a } b", c).0, ErrorClass::TemplateSlot);
    assert_eq!(class("{int(X)}", c).0, ErrorClass::TemplateSlot);
    let long = format!("{{{}(x)}}", "a".repeat(500));
    assert_eq!(class(&long, c).1.unwrap().chars().count(), 120);
    assert!(parse_template("{int(r99.x)}", &cols(c), &[], 100).is_ok());
    assert!(parse_template("{int(r5.x)}", &cols(c), &[], 5).is_err());
}

#[test]
fn braces_escape() {
    // round 2 (R1): a literal brace is outside the fixed-text charset, so an
    // escaped brace is refused at parse (template_slot)
    let e = parse_template("{{x}} and {int(x)}", &cols(&["x"]), &[p1()], 100).unwrap_err();
    assert_eq!(e.class, ErrorClass::TemplateSlot);
    let t = parse("x and {int(x)}", &["x"]);
    let f = fill(
        &t,
        &rs(&["x"], vec![vec![CellValue::Int(5)]]),
        &[],
        Lang::En,
    )
    .unwrap();
    assert_eq!(f.text, "x and 5");
    assert_eq!(f.printed.len(), 1);
}

#[test]
fn null_cell_refuses() {
    for slot in [
        "{money(x)}",
        "{int(x)}",
        "{date(x)}",
        "{cmp(x, y)}",
        "{list(x)}",
        "{percent(x)}",
    ] {
        let t = parse(slot, &["x", "y"]);
        let r = rs(&["x", "y"], vec![vec![CellValue::Null, CellValue::Int(1)]]);
        let e = fill(&t, &r, &[], Lang::En).unwrap_err();
        assert_eq!(e.class, ErrorClass::CheckFailed, "{slot}");
        assert_eq!(e.detail, None);
    }
    // no rows at all: a row-0 cell cannot be read
    let t = parse("{int(x)}", &["x"]);
    assert!(fill(&t, &rs(&["x"], vec![]), &[], Lang::En).is_err());
}

#[test]
fn non_number_refuses() {
    let t = parse("{money(x)}", &["x"]);
    let r = rs(&["x"], vec![vec![CellValue::Text("12".into())]]);
    assert_eq!(
        fill(&t, &r, &[], Lang::En).unwrap_err().class,
        ErrorClass::CheckFailed
    );
    for f in [f64::NAN, f64::INFINITY, 1e300, 1e-300] {
        assert!(format_money(&CellValue::Real(f), Lang::En).is_none(), "{f}");
    }
    assert_eq!(
        format_money(&CellValue::Real(1e21), Lang::En).unwrap().0,
        "1,000,000,000,000,000,000,000.00"
    );
    assert_eq!(
        format_money(&CellValue::Real(1e-7), Lang::En).unwrap().0,
        "0.00"
    );
}

#[test]
fn formatters() {
    let en = Lang::En;
    let da = Lang::Da;
    assert_eq!(
        format_number(&CellValue::Int(1234567), en).unwrap().0,
        "1,234,567"
    );
    assert_eq!(
        format_number(&CellValue::Real(1234.5), da).unwrap().0,
        "1.234,50"
    );
    assert_eq!(
        format_number(&CellValue::Real(-1234.5), en).unwrap().0,
        "-1,234.50"
    );
    assert_eq!(format_int(&CellValue::Real(2.5), en).unwrap().0, "2");
    assert_eq!(format_int(&CellValue::Real(3.5), en).unwrap().0, "4");
    assert_eq!(format_int(&CellValue::Real(-0.4), en).unwrap().0, "0");
    assert_eq!(
        format_percent(&CellValue::Real(12.5), en).unwrap().0,
        "12.5%"
    );
    assert_eq!(
        format_percent(&CellValue::Real(12.5), da).unwrap().0,
        "12,5 %"
    );
    let (t, d) = format_ratio_percent(&CellValue::Real(0.125), en).unwrap();
    assert_eq!((t.as_str(), d), ("12.5%", dec("12.5")));
    assert_eq!(
        format_ratio_percent(&CellValue::Real(0.1 + 0.2), en)
            .unwrap()
            .0,
        "30.0%"
    );
    assert_eq!(
        format_round(&CellValue::Real(1.23456), 3, en).unwrap().0,
        "1.235"
    );
    assert_eq!(format_round(&CellValue::Int(3), 0, en).unwrap().1, dec("3"));
    assert!(format_round(&CellValue::Int(3), 7, en).is_none());
    let d = |s: &str| CellValue::Text(s.into());
    assert_eq!(
        format_date(&d("2026-07-01"), en).unwrap(),
        ("1 July 2026".into(), "2026-07-01".into())
    );
    assert_eq!(format_date(&d("2026-07-01"), da).unwrap().0, "1. juli 2026");
    assert_eq!(
        format_date(&d("2024-02-29"), en).unwrap().0,
        "29 February 2024"
    );
    for bad in [
        "2025-02-29",
        "2026-13-01",
        "2026-7-1",
        "yesterday",
        "2026-07-01 ",
        "２０２６-07-01",
    ] {
        assert!(format_date(&d(bad), en).is_none(), "{bad}");
    }
}

#[test]
fn cmp_uses_money_precision() {
    let t = parse("{cmp(a, b)}", &["a", "b"]);
    let go = |a: f64, b: f64, l| {
        let r = rs(
            &["a", "b"],
            vec![vec![CellValue::Real(a), CellValue::Real(b)]],
        );
        fill(&t, &r, &[], l).unwrap().text
    };
    assert_eq!(go(10.001, 10.0, Lang::En), "equal to");
    assert_eq!(go(10.0, 10.02, Lang::En), "below");
    assert_eq!(go(10.0, 10.02, Lang::Da), "under");
    assert_eq!(go(5.0, 5.0, Lang::Da), "lig med");
}

#[test]
fn rows_total_rows_and_dates() {
    let mut r = rs(
        &["d"],
        vec![
            vec![CellValue::Text("2026-07-01".into())],
            vec![CellValue::Text("2026-08-15".into())],
        ],
    );
    let t = parse(
        "{rows()} of {total_rows()} on {date(d)} and {date(r1.d)}",
        &["d"],
    );
    let f = fill(&t, &r, &[], Lang::En).unwrap();
    assert_eq!(f.text, "2 of 2 on 1 July 2026 and 15 August 2026");
    assert_eq!(f.printed[2].dates, vec!["2026-07-01".to_string()]);
    r.truncated = true;
    r.total_rows = Some(2314);
    let f = fill(&t, &r, &[], Lang::Da).unwrap();
    assert!(
        f.text.starts_with("2 of 2.314 on 1. juli 2026"),
        "{}",
        f.text
    );
    assert_eq!(f.printed[1].values, vec![dec("2314")]);
    r.total_rows = None;
    assert!(fill(&t, &r, &[], Lang::En).is_err());
    let t = parse("{date(r5.d)}", &["d"]);
    assert!(fill(&t, &r, &[], Lang::En).is_err());
    let t = parse("{date(x)}", &["x"]);
    let r = rs(&["x"], vec![vec![CellValue::Text("hello".into())]]);
    assert_eq!(
        fill(&t, &r, &[], Lang::En).unwrap_err().class,
        ErrorClass::CheckFailed
    );
}

#[test]
fn param_empty_display_refuses() {
    let mut p = p1();
    p.display.clear();
    let t = parse_template("{param(p1)}", &cols(&["x"]), &[p.clone()], 100).unwrap();
    assert_eq!(
        fill(&t, &rs(&["x"], vec![]), &[p], Lang::En)
            .unwrap_err()
            .class,
        ErrorClass::CheckFailed
    );
}

#[test]
fn never_panics_on_hostile_utf8() {
    let hostile = [
        "İ{int(x)}İ",
        "K{money(x)}K",
        "ß{{ß}}ß",
        "e\u{301}{int(x)}\u{301}",
        "😀1{int(x)}2😀",
        "{",
        "}",
        "{{",
        "}}",
        "{}",
        "{int(",
        "{int(İ)}",
        "{int(x)}}",
        "{{{int(x)}",
        "{money(x, ŃOK)}",
        "{r1.İ}",
        "{round(x, ß)}",
        "{list(,)}",
        "{cmp(x,)}",
        "{😀}",
        "{int(r\u{301}1.x)}",
        "{int(x)}{",
    ];
    let texts = [
        "İ1",
        "K2",
        "ß",
        "e\u{301}3",
        "😀4😀",
        "{x}",
        "2026-07-01",
        "٣",
    ];
    for h in hostile {
        let c = cols(&["x", "İ", "K", "😀"]);
        if let Ok(t) = parse_template(h, &c, &[p1()], 100) {
            for tx in texts {
                let r = rs(
                    &["x", "İ", "K", "😀"],
                    vec![vec![
                        CellValue::Text(tx.into()),
                        CellValue::Int(1),
                        CellValue::Real(0.5),
                        CellValue::Null,
                    ]],
                );
                let _ = fill(&t, &r, &[p1()], Lang::Da);
            }
        }
    }
    let t = parse("{list(x)} on {date(x)} and {int(x)}", &["x"]);
    for tx in texts {
        let r = rs(&["x"], vec![vec![CellValue::Text(tx.into())]]);
        let _ = fill(&t, &r, &[], Lang::En);
    }
    // list verbatim text: spans stay on char boundaries
    let t = parse("é {list(x)} og", &["x"]);
    let r = rs(&["x"], vec![vec![CellValue::Text("İ😀".into())]]);
    let f = fill(&t, &r, &[], Lang::En).unwrap();
    let p = &f.printed[0];
    assert!(f.text.is_char_boundary(p.start) && f.text.is_char_boundary(p.end));
    assert_eq!(&f.text[p.start..p.end], "- İ😀");
    assert!(p.values.is_empty());
}

#[test]
fn every_bound_question_param_is_used_or_shown() {
    // Plan 45 final review I3 (ruling F-c): "open invoices total in Q3 2026"
    // answered by a method that ignores the date range is another question.
    let q3 = Param {
        name: "p2".into(),
        ty: ParamType::DateRange,
        bound: Some(Bound::DateRange("2026-07-01".into(), "2026-10-01".into())),
        display: "Q3 2026".into(),
    };
    let ps = vec![common::entity(1), q3];
    let all_time = "SELECT SUM(i.amount) AS total FROM invoices i \
        JOIN customers c ON c.id = i.customer_id WHERE c.id = :p1";
    let in_q3 = format!("{all_time} AND i.issued >= :p2_from AND i.issued < :p2_to");
    let unused = common::v(all_time, &ps);
    let used = common::v(&in_q3, &ps);
    let c = cols(&["total"]);
    let plain = parse_template("{param(p1)} owes {money(total)}.", &c, &ps, 100).unwrap();
    let shown = parse_template(
        "{param(p1)} owes {money(total)} in {param(p2)}.",
        &c,
        &ps,
        100,
    )
    .unwrap();
    assert_eq!(plain.param_slots(), vec!["p1"]);
    assert_eq!(shown.param_slots(), vec!["p1", "p2"]);
    // Bound but neither used nor shown: refused.
    let e = check_params_covered(&unused, &plain, &ps).unwrap_err();
    assert_eq!(e.class, ErrorClass::ParamMisuse);
    assert_eq!(e.detail, None);
    // Used by the method: ok.
    check_params_covered(&used, &plain, &ps).unwrap();
    // Ruling F-f (final review part 2): a filter the template shows but the
    // method ignores is refused ("in Q3 2026" over an all-time total). This
    // replaces the part-1 assertion that accepted it.
    let e = check_params_covered(&unused, &shown, &ps).unwrap_err();
    assert_eq!(e.class, ErrorClass::ParamMisuse);
    check_params_covered(&used, &shown, &ps).unwrap();
    // An unbound draft parameter is not judged.
    let mut draft = ps.clone();
    draft[1].bound = None;
    check_params_covered(&unused, &plain, &draft).unwrap();
}

#[test]
fn every_bound_param_is_used_even_a_shown_threshold() {
    // Plan 45 final review part 3 (ruling F-g): "total of invoices over 5000"
    // answered by a method that ignores the 5000 and a template that echoes
    // it ("Invoices over {param(p2)} total ...") is a confidently wrong
    // number. A `cmp` slot compares two result cells and has no parameter
    // operand, so no template can use an unused threshold legitimately:
    // every bound parameter, threshold or filter, must be used by the method.
    let base = vec![common::entity(1)];
    let method = common::v(
        "SELECT SUM(i.amount) AS total, c.credit_limit FROM invoices i \
         JOIN customers c ON c.id = i.customer_id WHERE c.id = :p1",
        &base,
    );
    let c = cols(&["total", "credit_limit"]);
    let thresholds = [
        (ParamType::Amount, Bound::Amount(dec("5000"))),
        (ParamType::Integer, Bound::Integer(3)),
        (ParamType::Percent, Bound::Percent(dec("10"))),
    ];
    let others = [
        (ParamType::Date, Bound::Date("2026-07-01".into())),
        (
            ParamType::Text {
                table: "customers".into(),
                column: "city".into(),
            },
            Bound::Text("Aarhus".into()),
        ),
    ];
    for (ty, bound) in thresholds.iter().chain(others.iter()) {
        let mut ps = base.clone();
        ps.push(Param {
            name: "p2".into(),
            ty: ty.clone(),
            bound: Some(bound.clone()),
            display: "x".into(),
        });
        // Echo only.
        let echo = parse_template(
            "Invoices over {param(p2)} total {money(total)}.",
            &c,
            &ps,
            100,
        )
        .unwrap();
        let e = check_params_covered(&method, &echo, &ps).unwrap_err();
        assert_eq!(e.class, ErrorClass::ParamMisuse, "{ty:?}");
        assert_eq!(e.detail, None, "{ty:?}");
        // Echo next to a cmp of cells: still refused (the cmp never reads p2).
        let with_cmp = parse_template(
            "Is {param(p1)} over {param(p2)}? Owes {money(total)}, \
             {cmp(total, credit_limit)} the limit.",
            &c,
            &ps,
            100,
        )
        .unwrap();
        let e = check_params_covered(&method, &with_cmp, &ps).unwrap_err();
        assert_eq!(e.class, ErrorClass::ParamMisuse, "{ty:?}");
    }
    // A threshold the method uses may be echoed.
    for (ty, bound) in &thresholds[..2] {
        let mut ps = base.clone();
        ps.push(Param {
            name: "p2".into(),
            ty: ty.clone(),
            bound: Some(bound.clone()),
            display: "x".into(),
        });
        let used = common::v(
            "SELECT SUM(i.amount) AS total, c.credit_limit FROM invoices i \
             JOIN customers c ON c.id = i.customer_id WHERE c.id = :p1 AND i.amount > :p2",
            &ps,
        );
        let echo = parse_template(
            "Invoices over {param(p2)} total {money(total)}.",
            &c,
            &ps,
            100,
        )
        .unwrap();
        check_params_covered(&used, &echo, &ps).unwrap();
    }
}

#[test]
fn compound_scale_words_refused() {
    // Plan 45 final review M6: a word next to a number that contains a scale
    // stem is a scale word.
    for w in [
        "hundredthousand",
        "tenthousand",
        "Hundredmillion",
        "halvmilliard",
        "totusind",
        "trillionen",
        "femmio",
        "tremia",
    ] {
        for tpl in [
            format!("It is {{money(x)}} {w} now."),
            format!("It is {w} {{money(x)}} now."),
        ] {
            let (c, _) = class(&tpl, &["x"]);
            assert_eq!(c, ErrorClass::TemplateSlot, "{tpl}");
        }
    }
    // A word without a stem next to a number is fine.
    parse("It is {money(x)} kroner now.", &["x"]);
}

// ---- final review part 5 ----

/// A draft as plan 44 leaves it: the entity bound, its `display` the
/// snapshot's (name, first `show` value, key). Here the show value is an
/// email and the name and key are Identifier columns.
fn anna_draft(original: &str, text: &str, lang: Lang) -> saiife_shield::question::Draft {
    saiife_shield::question::Draft {
        lang,
        original: original.into(),
        text: text.into(),
        params: vec![Param {
            name: "p1".into(),
            ty: ParamType::Entity {
                table: "customers".into(),
                word: "customer".into(),
            },
            bound: Some(Bound::Keys(vec![4411])),
            display: "Anna Berg, anna.berg@example.dk (customer #4411)".into(),
        }],
        pending: vec![],
    }
}

const SNAPSHOT_BITS: [&str; 5] = ["Anna Berg", "anna.berg@", "example.dk", "4411", "#"];

#[test]
fn entity_param_prints_only_the_users_words() {
    // Ruling F-n: the answer names the entity with the user's own words.
    use saiife_shield::template::{answer_params, empty_for_key_reason, spoken};
    let d = anna_draft("What does anna berg owe?", "What does :p1 owe?", Lang::En);
    assert_eq!(spoken(&d, "p1").as_deref(), Some("anna berg"));
    let ps = answer_params(&d, &common::schema());
    assert_eq!(ps[0].display, "anna berg");
    assert_eq!(ps[0].bound, d.params[0].bound);
    let c = cols(&["total"]);
    let t = parse_template("{param(p1)} owes {money(total)}.", &c, &ps, 100).unwrap();
    let f = fill(
        &t,
        &rs(&["total"], vec![vec![CellValue::Real(412.0)]]),
        &ps,
        Lang::En,
    )
    .unwrap();
    assert_eq!(f.text, "anna berg owes 412.00.");
    let why = empty_for_key_reason(&d, &common::schema(), "p1");
    assert_eq!(why, "the method found no rows for anna berg");
    for bit in SNAPSHOT_BITS {
        assert!(!f.text.contains(bit), "{bit} in {}", f.text);
        assert!(!why.contains(bit), "{bit} in {why}");
    }
    // Danish.
    let d = anna_draft("Hvad skylder Anna Berg?", "Hvad skylder :p1?", Lang::Da);
    let ps = answer_params(&d, &common::schema());
    assert_eq!(ps[0].display, "Anna Berg");
    assert_eq!(
        empty_for_key_reason(&d, &common::schema(), "p1"),
        "metoden fandt ingen rækker for Anna Berg"
    );
}

#[test]
fn entity_param_falls_back_to_the_plain_word() {
    // Ruling F-n: when the user's span cannot be told apart, the entity
    // type's plain word.
    use saiife_shield::template::{answer_params, empty_for_key_reason, spoken};
    let mut d = anna_draft("Berg and Berg and Berg", ":p1 and :p2", Lang::En);
    let mut p2 = d.params[0].clone();
    p2.name = "p2".into();
    d.params.push(p2);
    assert_eq!(spoken(&d, "p1"), None);
    assert_eq!(spoken(&d, "p2"), None);
    let ps = answer_params(&d, &common::schema());
    assert_eq!(ps[0].display, "the customer");
    assert_eq!(ps[1].display, "the customer");
    assert_eq!(
        empty_for_key_reason(&d, &common::schema(), "p1"),
        "the method found no rows for the customer"
    );
    let mut da = d.clone();
    da.lang = Lang::Da;
    assert_eq!(
        answer_params(&da, &common::schema())[0].display,
        "pågældende kunde"
    );
    // A draft whose text does not fit its original: the plain word too.
    let d = anna_draft("What does anna owe?", "What is :p1 owing?", Lang::En);
    assert_eq!(spoken(&d, "p1"), None);
    assert_eq!(
        answer_params(&d, &common::schema())[0].display,
        "the customer"
    );
    // Non-entity parameters keep their display.
    let mut d = anna_draft(
        "anna: invoices over 5000",
        ":p1: invoices over :p2",
        Lang::En,
    );
    d.params.push(Param {
        name: "p2".into(),
        ty: ParamType::Amount,
        bound: Some(Bound::Amount(dec("5000"))),
        display: "5,000.00".into(),
    });
    let ps = answer_params(&d, &common::schema());
    assert_eq!(ps[0].display, "anna");
    assert_eq!(ps[1].display, "5,000.00");
}

#[test]
fn no_limit_covers_a_param() {
    // Ruling F-p (supersedes F-o): plan 44's binding has no row-count role,
    // so no parameter is covered by a LIMIT. "Customers who bought more than
    // 10 items" (p2 = 10, a filter) answered by a method with LIMIT 10 and no
    // comparison would look right and be wrong. The part-5 "top 5 / LIMIT 5
    // passes" assertion flips to refused: required by the finding.
    let int = |name: &str, n: i64| Param {
        name: name.into(),
        ty: ParamType::Integer,
        bound: Some(Bound::Integer(n)),
        display: n.to_string(),
    };
    let c = cols(&["city", "total"]);
    let method = |n: u32, ps: &[Param]| {
        common::v(
            &format!(
                "SELECT c.city, SUM(i.amount) AS total FROM invoices i JOIN customers c \
                 ON c.id = i.customer_id GROUP BY c.city ORDER BY total DESC LIMIT {n}"
            ),
            ps,
        )
    };
    // "top 5 cities by total" with LIMIT 5: refused (no row-count role yet).
    let ps = vec![int("p2", 5)];
    let t = parse_template("{list(city, total)}", &c, &ps, 100).unwrap();
    let e = check_params_covered(&method(5, &ps), &t, &ps).unwrap_err();
    assert_eq!(e.class, ErrorClass::ParamMisuse);
    // "more than 10 items" with LIMIT 10 and no comparison: refused.
    let ps = vec![int("p2", 10)];
    let t = parse_template("{list(city, total)}", &c, &ps, 100).unwrap();
    let e = check_params_covered(&method(10, &ps), &t, &ps).unwrap_err();
    assert_eq!(e.class, ErrorClass::ParamMisuse);
    // The same threshold applied as a comparison: used.
    let used = common::v(
        "SELECT c.city, COUNT(*) AS total FROM invoices i JOIN customers c \
         ON c.id = i.customer_id GROUP BY c.city HAVING COUNT(*) > :p2 LIMIT 10",
        &ps,
    );
    check_params_covered(&used, &t, &ps).unwrap();
    // Two params both equal to 10, both unused: neither is covered by the
    // LIMIT, so each one alone is refused too.
    let both = vec![int("p2", 10), int("p3", 10)];
    let t = parse_template("{list(city, total)}", &c, &both, 100).unwrap();
    let m = method(10, &both);
    assert!(m.params_used.is_empty());
    let e = check_params_covered(&m, &t, &both).unwrap_err();
    assert_eq!(e.class, ErrorClass::ParamMisuse);
    for one in [&both[..1], &both[1..]] {
        let e = check_params_covered(&m, &t, one).unwrap_err();
        assert_eq!(e.class, ErrorClass::ParamMisuse);
    }
    // LIMIT :pN stays refused by the validator.
    let e = saiife_shield::sql::validate(
        "SELECT c.city, SUM(i.amount) AS total FROM invoices i JOIN customers c \
         ON c.id = i.customer_id GROUP BY c.city ORDER BY total DESC LIMIT :p2",
        &common::schema(),
        &common::public(),
        &ps,
    )
    .unwrap_err();
    assert_eq!(e.class, ErrorClass::ConstructNotAllowed);
}
