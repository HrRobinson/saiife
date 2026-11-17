//! Plan 44 Task 1: language, number words and literal parsing.

use saiife_shield::lang::*;
use saiife_shield::schema::{Decimal, Lang};

fn d(s: &str) -> Decimal {
    Decimal::parse_plain(s).unwrap()
}

fn one(text: &str, lang: Lang) -> Literal {
    let v = find_literals(text, lang).unwrap();
    assert_eq!(v.len(), 1, "{text}: {v:?}");
    assert_eq!((v[0].start, v[0].end), (0, text.len()), "{text}");
    v[0].lit.clone()
}

fn amount(v: &str, cur: Option<&str>) -> Literal {
    Literal::Amount {
        value: d(v),
        currency: cur.map(str::to_string),
    }
}

fn range(a: &str, b: &str) -> Literal {
    Literal::DateRange {
        from: a.into(),
        to_exclusive: b.into(),
    }
}

fn word(lang: Lang, t: &str) -> Option<Decimal> {
    number_words(lang)
        .parse_at(t, 0)
        .and_then(|(e, v)| (e == t.len()).then_some(v))
}

#[test]
fn detects_danish() {
    assert_eq!(detect_lang("Hvad skylder Anna Berg?"), Lang::Da);
    assert_eq!(detect_lang("What does Anna owe?"), Lang::En);
    assert_eq!(detect_lang("Søren"), Lang::Da);
}

#[test]
fn parses_amounts() {
    assert_eq!(one("10 000", Lang::En), amount("10000", None));
    assert_eq!(one("10.000,50", Lang::Da), amount("10000.50", None));
    assert_eq!(one("10.000,50", Lang::En), amount("10000.50", None));
    assert_eq!(one("10,000.50", Lang::En), amount("10000.50", None));
    assert_eq!(one("15k", Lang::En), amount("15000", None));
    assert_eq!(one("kr. 500", Lang::Da), amount("500", Some("kr")));
    assert_eq!(one("500 NOK", Lang::En), amount("500", Some("NOK")));
    assert_eq!(one("$1,500", Lang::En), amount("1500", Some("USD")));
    assert_eq!(one("500,-", Lang::Da), amount("500", Some("kr")));
    assert_eq!(one("3", Lang::En), Literal::Integer(3));
    assert_eq!(one("15%", Lang::En), Literal::Percent(d("15")));
    assert_eq!(one("12,5 procent", Lang::Da), Literal::Percent(d("12.5")));
}

#[test]
fn parses_dates() {
    assert_eq!(
        one("2026-07-01", Lang::En),
        Literal::Date("2026-07-01".into())
    );
    assert_eq!(
        one("1 July 2026", Lang::En),
        Literal::Date("2026-07-01".into())
    );
    assert_eq!(
        one("1. juli 2026", Lang::Da),
        Literal::Date("2026-07-01".into())
    );
    assert_eq!(
        one("1.7.2026", Lang::Da),
        Literal::Date("2026-07-01".into())
    );
    assert_eq!(
        one("July 1, 2026", Lang::En),
        Literal::Date("2026-07-01".into())
    );
    let q3 = range("2026-07-01", "2026-10-01");
    assert_eq!(one("Q3 2026", Lang::En), q3);
    assert_eq!(one("3. kvartal 2026", Lang::Da), q3);
    assert_eq!(one("third quarter 2026", Lang::En), q3);
    assert_eq!(
        one("juli 2026", Lang::Da),
        range("2026-07-01", "2026-08-01")
    );
    assert_eq!(
        one("December 2026", Lang::En),
        range("2026-12-01", "2027-01-01")
    );
    assert_eq!(one("Q4 2026", Lang::En), range("2026-10-01", "2027-01-01"));
    assert_eq!(one("2026", Lang::En), range("2026-01-01", "2027-01-01"));
    assert!(find_literals("2026-02-30", Lang::En).is_err());
    assert!(find_literals("5. kvartal 2026", Lang::Da).is_err());
    let ds = find_dates("fra 1. juli 2026 til 2026-08-01", Lang::Da);
    assert_eq!(ds.len(), 2);
    assert_eq!(ds[1].2, "2026-08-01");
}

#[test]
fn number_words_en() {
    assert_eq!(word(Lang::En, "twenty-one"), Some(d("21")));
    assert_eq!(word(Lang::En, "twenty one"), Some(d("21")));
    assert_eq!(word(Lang::En, "three hundred and five"), Some(d("305")));
    assert_eq!(word(Lang::En, "a dozen"), Some(d("12")));
    assert_eq!(word(Lang::En, "two dozen"), Some(d("24")));
    assert_eq!(word(Lang::En, "a thousand"), Some(d("1000")));
    assert_eq!(
        word(Lang::En, "one million two thousand five"),
        Some(d("1002005"))
    );
    assert_eq!(word(Lang::En, "first"), Some(d("1")));
    assert_eq!(word(Lang::En, "twelfth"), Some(d("12")));
    assert_eq!(word(Lang::En, "a"), None);
    assert_eq!(word(Lang::En, "an"), None);
    assert_eq!(word(Lang::En, "to"), None);
    let nw = number_words(Lang::En);
    assert!(nw.is_number_word("hundred") && !nw.is_number_word("a"));
}

#[test]
fn number_words_da() {
    assert_eq!(word(Lang::Da, "enogtyve"), Some(d("21")));
    assert_eq!(word(Lang::Da, "halvtreds"), Some(d("50")));
    assert_eq!(word(Lang::Da, "femoghalvtreds"), Some(d("55")));
    assert_eq!(word(Lang::Da, "to hundrede og fem"), Some(d("205")));
    assert_eq!(word(Lang::Da, "ti tusind"), Some(d("10000")));
    assert_eq!(word(Lang::Da, "første"), Some(d("1")));
    assert_eq!(word(Lang::Da, "én"), Some(d("1")));
    assert_eq!(word(Lang::Da, "ét"), Some(d("1")));
    assert_eq!(word(Lang::Da, "en"), None);
    assert_eq!(word(Lang::Da, "et"), None);
    assert_eq!(word(Lang::Da, "to"), Some(d("2")));
    assert_eq!(word(Lang::En, "to"), None);
    let v = find_literals("mere end ti tusind", Lang::Da).unwrap();
    assert_eq!(v.len(), 1);
    assert_eq!((v[0].start, v[0].end), (9, 18));
    assert_eq!(v[0].lit, amount("10000", None));
}

#[test]
fn find_numbers_mixed() {
    let t = "18,420.00 NOK across 3 open invoices, 15% over";
    let v = find_numbers(t, Lang::En);
    assert_eq!(v.len(), 3);
    assert_eq!(v[0], (0, 9, d("18420.00")));
    assert_eq!(&t[v[1].0..v[1].1], "3");
    assert_eq!(v[1].2, d("3"));
    assert_eq!(&t[v[2].0..v[2].1], "15%");
    assert_eq!(v[2].2, d("15"));
    let w = find_numbers("send tre fakturaer og twenty-one more", Lang::Da);
    assert_eq!(w.len(), 1);
    assert_eq!(w[0].2, d("3"));
}

#[test]
fn danish_grouping() {
    let v = find_numbers("18.420,00 kr", Lang::Da);
    assert_eq!(v, vec![(0, 9, d("18420.00"))]);
    let v = find_numbers("18 420,00 kr", Lang::Da);
    assert_eq!(v[0].2, d("18420.00"));
}

#[test]
fn bad_literal_refuses() {
    let e = find_literals("over 10,0,0", Lang::En).unwrap_err();
    assert_eq!((e.start, e.end), (5, 11));
    assert!(!e.to_string().contains("10,0,0"));
}

#[test]
fn literals_in_a_question() {
    let t = "Hvilke kunder skylder mere end 10.000,50 kr. i 3. kvartal 2026?";
    let v = find_literals(t, Lang::Da).unwrap();
    assert_eq!(v.len(), 2, "{v:?}");
    assert_eq!(v[0].lit, amount("10000.50", Some("kr")));
    assert_eq!(v[1].lit, range("2026-07-01", "2026-10-01"));
    assert_eq!(&t[v[1].start..v[1].end], "3. kvartal 2026");
    let t = "over 10k from 1 July 2026 across a dozen customers";
    let v = find_literals(t, Lang::En).unwrap();
    assert_eq!(v.len(), 3);
    assert_eq!(v[2].lit, Literal::Integer(12));
}

#[test]
fn kelvin_and_dotted_i_never_panic() {
    for t in [
        "5\u{212A}",
        "5\u{212A}r",
        "500 \u{212A}r",
        "July 5\u{212A}",
        "5\u{130}",
        "5\u{df}",
        "5\u{17f}t",
        "5\u{130}nd",
        "1\u{212A}\u{212A}",
        "Q3\u{212A} 2026",
    ] {
        for l in [Lang::En, Lang::Da] {
            let _ = find_literals(t, l);
            let _ = find_numbers(t, l);
            let _ = find_dates(t, l);
            let _ = detect_lang(t);
        }
    }
    // the Kelvin sign is not the multiplier k
    assert_eq!(find_numbers("5\u{212A}", Lang::En)[0].2, d("5"));
}

#[test]
fn non_ascii_numerics_are_seen() {
    let n = |t: &str| find_numbers(t, Lang::En);
    assert_eq!(n("x\u{b2}")[0].2, d("2"));
    assert_eq!(n("\u{ff15}")[0].2, d("5"));
    assert_eq!(n("\u{ff15}\u{ff15}")[0], (0, 6, d("55")));
    for t in ["\u{661}\u{662}\u{663}", "\u{bd}", "\u{2153}"] {
        assert!(n(t).is_empty(), "{t}");
        assert_eq!(find_unreadable_numerics(t), vec![(0, t.len())], "{t}");
    }
    assert!(find_unreadable_numerics("\u{b2} \u{ff15} 12").is_empty());
    for t in [
        "x\u{b2}",
        "\u{ff15}",
        "\u{661}\u{662}\u{663}",
        "\u{bd}",
        "\u{2153}",
    ] {
        let e = find_literals(t, Lang::En).unwrap_err();
        assert!(e.end > e.start);
    }
}

fn xorshift(s: &mut u64) -> u64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s
}

#[test]
fn never_panics_on_any_utf8() {
    let frags = [
        "5",
        "10",
        "2026",
        "1",
        ",",
        ".",
        " ",
        "-",
        "%",
        "k",
        "K",
        "m",
        "st",
        "nd",
        "rd",
        "th",
        "\u{212A}",
        "\u{130}",
        "\u{df}",
        "\u{17f}",
        "æ",
        "ø",
        "å",
        "\u{1f600}",
        "e\u{301}",
        "\u{5d0}\u{5d1}",
        "\u{627}\u{644}",
        "\u{661}",
        "\u{ff15}",
        "\u{b2}",
        "\u{bd}",
        "July",
        "juli",
        "Q3",
        "kr.",
        "$",
        "€",
        "twenty",
        "one",
        "a",
        "en",
        "og",
        "and",
        "hundred",
        "tusind",
        "kvartal",
        "quarter",
        "\u{a0}",
        "\u{202f}",
        "of",
        "2026-07-01",
        "1.7.2026",
    ];
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    for _ in 0..4000 {
        let n = 1 + xorshift(&mut seed) % 8;
        let mut t = String::new();
        for _ in 0..n {
            t.push_str(frags[(xorshift(&mut seed) % frags.len() as u64) as usize]);
        }
        let _ = detect_lang(&t);
        let _ = find_unreadable_numerics(&t);
        for l in [Lang::En, Lang::Da] {
            let _ = find_literals(&t, l);
            let _ = find_numbers(&t, l);
            let _ = find_dates(&t, l);
            let nw = number_words(l);
            for (i, _) in t.char_indices() {
                let _ = nw.parse_at(&t, i);
            }
            let _ = nw.parse_at(&t, t.len());
            let _ = nw.is_number_word(&t);
        }
    }
}
