//! Plan 44 T3: the question parameterizer and the local resolution steps
//! (spec §2.1.6, §2.1.7). Every name here is made up.

#[path = "fixtures.rs"]
mod fixtures;

use fixtures::Rng;
use saiife_shield::lexicon::{build_lexicon, Lexicon, MAX_CANDIDATES};
use saiife_shield::ner::{DetectError, ListDetector, NameDetector, NameSpan, SpanLabel};
use saiife_shield::question::{
    answer, parameterize, template_key, Answer, Draft, Pending, Refusal, Step,
};
use saiife_shield::schema::{
    Bound, ColType, ColumnClass, ColumnInfo, Decimal, EntitySpec, Lang, ParamType, Schema,
    TableInfo,
};
use saiife_shield::snapshot::build_snapshot;
use saiife_shield::source::{Cell, SourceTable, VecSource};
use tempfile::TempDir;

const COLS: [(&str, ColType, ColumnClass); 5] = [
    ("id", ColType::Integer, ColumnClass::Identifier),
    ("first_name", ColType::Text, ColumnClass::Identifier),
    ("last_name", ColType::Text, ColumnClass::Identifier),
    ("city", ColType::Text, ColumnClass::Quasi),
    ("segment", ColType::Text, ColumnClass::Public),
];

fn schema(rows: u64) -> Schema {
    Schema {
        dataset: "crm".parse().unwrap(),
        tables: vec![TableInfo {
            name: "customers".into(),
            alias: None,
            rows,
            columns: COLS
                .iter()
                .map(|(n, ty, class)| ColumnInfo {
                    name: (*n).into(),
                    ty: *ty,
                    class: *class,
                    alias: None,
                })
                .collect(),
        }],
        entities: vec![EntitySpec {
            table: "customers".into(),
            key: "id".into(),
            names: vec!["first_name".into(), "last_name".into()],
            show: vec!["city".into()],
            word: "customer".into(),
            word_da: "kunde".into(),
        }],
        joins: vec![],
    }
}

/// (first, last, city): ids 1, 2, 3, ... in order.
const PEOPLE: [(&str, &str, &str); 5] = [
    ("Anna", "Berg", "Aarhus"),
    ("Anna", "Berg", "Odense"),
    ("Søren", "Ærø", "Aalborg"),
    ("Freja", "Lund", "Esbjerg"),
    ("Ida", "Bo", "Odense"),
];
/// Mette Hansen is in the fixture more often than MAX_CANDIDATES.
const METTES: usize = 25;

struct Fx {
    _dir: TempDir,
    lex: Lexicon,
    schema: Schema,
}

fn fx() -> Fx {
    let mut names: Vec<(&str, &str, &str)> = PEOPLE.to_vec();
    names.extend(std::iter::repeat_n(("Mette", "Hansen", "Leeds"), METTES));
    let rows: Vec<Vec<Cell>> = names
        .iter()
        .enumerate()
        .map(|(i, (f, l, c))| {
            vec![
                Cell::Int(i as i64 + 1),
                Cell::Text((*f).into()),
                Cell::Text((*l).into()),
                Cell::Text((*c).into()),
                // A public value with a digit in it (ruling P-29).
                Cell::Text(if *f == "Mette" { "B2B" } else { "retail" }.into()),
            ]
        })
        .collect();
    let n = rows.len() as u64;
    let mut src = VecSource {
        tables: vec![(
            SourceTable {
                name: "customers".into(),
                columns: COLS.iter().map(|c| c.0.to_string()).collect(),
            },
            rows,
        )],
    };
    let dir = tempfile::tempdir().unwrap();
    let ds = dir.path().join("ds");
    let info = build_snapshot(&mut src, &ds, &mut |_| {}).unwrap();
    let lexp = ds.join("lexicon.sqlite");
    let schema = schema(n);
    build_lexicon(&info.path, &schema, &lexp).unwrap();
    Fx {
        _dir: dir,
        lex: Lexicon::open(&lexp).unwrap(),
        schema,
    }
}

fn none() -> ListDetector {
    ListDetector::new(&[])
}

fn dec(s: &str) -> Decimal {
    Decimal::parse_plain(s).unwrap()
}

fn ready(s: Step) -> Draft {
    match s {
        Step::Ready(d) => d,
        other => panic!("expected Ready, got {other:?}"),
    }
}

fn ask(s: Step) -> Draft {
    match s {
        Step::Ask(d) => d,
        other => panic!("expected Ask, got {other:?}"),
    }
}

fn refusal(s: Step) -> Refusal {
    match s {
        Step::Refuse(r) => r,
        other => panic!("expected Refuse, got {other:?}"),
    }
}

fn customers() -> ParamType {
    ParamType::Entity {
        table: "customers".into(),
        word: "customer".into(),
    }
}

fn run(f: &Fx, q: &str, det: &dyn NameDetector) -> Step {
    parameterize(q, None, &f.schema, &f.lex, det).unwrap()
}

#[test]
fn simple_entity_and_amount() {
    let f = fx();
    let d = ready(run(
        &f,
        "What does Søren Ærø owe, and is it over 10 000?",
        &none(),
    ));
    // Ruling P-27 (was R44-1): the function words decide; a Danish name in
    // an English question leaves it English.
    assert_eq!(d.lang, Lang::En);
    assert_eq!(d.text, "What does :p1 owe, and is it over :p2?");
    assert_eq!(d.params.len(), 2);
    assert_eq!(d.params[0].name, "p1");
    assert_eq!(d.params[0].ty, customers());
    assert_eq!(d.params[0].bound, Some(Bound::Keys(vec![3])));
    assert_eq!(d.params[0].display, "Søren Ærø, Aalborg (customer #3)");
    assert_eq!(d.params[1].name, "p2");
    assert_eq!(d.params[1].ty, ParamType::Amount);
    assert_eq!(d.params[1].bound, Some(Bound::Amount(dec("10000"))));
    assert_eq!(d.params[1].display, "10 000");
    assert!(d.pending.is_empty());
}

#[test]
fn two_matches_ask_pick() {
    let f = fx();
    let d = ask(run(&f, "What does Anna Berg owe?", &none()));
    assert_eq!(d.text, "What does :p1 owe?");
    match &d.pending[0] {
        Pending::Pick {
            param,
            word,
            candidates,
            too_many,
        } => {
            assert_eq!(param, "p1");
            assert_eq!(word, "customer");
            assert_eq!(candidates.len(), 2);
            assert!(!too_many);
            let keys: Vec<i64> = candidates.iter().map(|c| c.key).collect();
            assert_eq!(keys, vec![1, 2]);
        }
        other => panic!("expected Pick, got {other:?}"),
    }
    assert_eq!(d.params[0].bound, None);
    let d = ready(answer(d, Answer::Pick(2), &f.lex).unwrap());
    assert_eq!(d.params[0].bound, Some(Bound::Keys(vec![2])));
    assert_eq!(d.params[0].display, "Anna Berg, Odense (customer #2)");
    assert_eq!(d.text, "What does :p1 owe?");
    assert!(d.pending.is_empty());
}

#[test]
fn pick_none_of_these_and_out_of_range() {
    let f = fx();
    let d = ask(run(&f, "What does Anna Berg owe?", &none()));
    match refusal(answer(d.clone(), Answer::Pick(0), &f.lex).unwrap()) {
        Refusal::NoMatch { word, written } => {
            assert_eq!(word, "customer");
            assert_eq!(written, "Anna Berg");
        }
        other => panic!("{other:?}"),
    }
    assert!(answer(d.clone(), Answer::Pick(3), &f.lex).is_err());
    // An answer of the wrong kind is a caller bug.
    assert!(answer(d.clone(), Answer::DidYouMean(true), &f.lex).is_err());
    assert!(answer(d, Answer::KeepName(true), &f.lex).is_err());
}

#[test]
fn too_many_lists_the_first_and_none_refuses() {
    let f = fx();
    let d = ask(run(&f, "What does Mette Hansen owe?", &none()));
    match &d.pending[0] {
        Pending::Pick {
            candidates,
            too_many,
            ..
        } => {
            assert!(*too_many);
            assert_eq!(candidates.len(), MAX_CANDIDATES);
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        refusal(answer(d.clone(), Answer::Pick(0), &f.lex).unwrap()),
        Refusal::TooMany { word } if word == "customer"
    ));
    let d = ready(answer(d, Answer::Pick(MAX_CANDIDATES), &f.lex).unwrap());
    assert!(matches!(&d.params[0].bound, Some(Bound::Keys(k)) if k.len() == 1));
}

#[test]
fn no_match_refuses() {
    let f = fx();
    let det = ListDetector::new(&[("Zed Zulu", SpanLabel::Person)]);
    let d = ask(run(&f, "What does Zed Zulu owe?", &det));
    assert!(d.params.is_empty());
    match &d.pending[0] {
        Pending::KeepName { span, name } => {
            assert_eq!(name, "Zed Zulu");
            assert_eq!(*span, (10, 18));
        }
        other => panic!("{other:?}"),
    }
    match refusal(answer(d.clone(), Answer::KeepName(false), &f.lex).unwrap()) {
        Refusal::NameRefused { name } => assert_eq!(name, "Zed Zulu"),
        other => panic!("{other:?}"),
    }
    // After a verified touch the name stays as plain text.
    let d = ready(answer(d, Answer::KeepName(true), &f.lex).unwrap());
    assert_eq!(d.text, "What does Zed Zulu owe?");
    assert!(d.params.is_empty());
}

#[test]
fn typo_offers_did_you_mean() {
    let f = fx();
    let det = ListDetector::new(&[("Ana Berg", SpanLabel::Person)]);
    let d = ask(run(&f, "What does Ana Berg owe?", &det));
    assert_eq!(d.text, "What does :p1 owe?");
    match &d.pending[0] {
        Pending::DidYouMean {
            param,
            word,
            written,
            suggestion,
        } => {
            assert_eq!(word, "customer");
            assert_eq!(param, "p1");
            assert_eq!(written, "Ana Berg");
            assert_eq!(suggestion.display, "Anna Berg");
        }
        other => panic!("{other:?}"),
    }
    // Yes: the suggestion resolves again, to the two Annas.
    let yes = ask(answer(d.clone(), Answer::DidYouMean(true), &f.lex).unwrap());
    match &yes.pending[0] {
        Pending::Pick { candidates, .. } => assert_eq!(candidates.len(), 2),
        other => panic!("{other:?}"),
    }
    let yes = ready(answer(yes, Answer::Pick(1), &f.lex).unwrap());
    assert_eq!(yes.params[0].bound, Some(Bound::Keys(vec![1])));
    assert_eq!(yes.params[0].ty, customers());
    // No: keeping the name as text needs the touch.
    let no = ask(answer(d, Answer::DidYouMean(false), &f.lex).unwrap());
    assert_eq!(no.text, "What does Ana Berg owe?");
    assert!(no.params.is_empty());
    assert!(matches!(&no.pending[0], Pending::KeepName { name, .. } if name == "Ana Berg"));
}

#[test]
fn typo_with_one_match_resolves_on_yes() {
    let f = fx();
    let det = ListDetector::new(&[("Sören Ærø", SpanLabel::Person)]);
    let d = ask(run(&f, "Hvad skylder Sören Ærø?", &det));
    assert_eq!(d.lang, Lang::Da);
    let d = ready(answer(d, Answer::DidYouMean(true), &f.lex).unwrap());
    assert_eq!(d.params[0].bound, Some(Bound::Keys(vec![3])));
    assert_eq!(d.params[0].display, "Søren Ærø, Aalborg (kunde #3)");
    assert_eq!(d.text, "Hvad skylder :p1?");
}

#[test]
fn lowercase_danish_name_resolves() {
    let f = fx();
    let d = ready(run(&f, "hvad skylder søren ærø", &none()));
    assert_eq!(d.lang, Lang::Da);
    assert_eq!(d.text, "hvad skylder :p1");
    assert_eq!(d.params[0].bound, Some(Bound::Keys(vec![3])));
    assert_eq!(d.params[0].display, "Søren Ærø, Aalborg (kunde #3)");
}

#[test]
fn danish_and_shorthand_literals() {
    let f = fx();
    let d = ready(
        parameterize(
            "over 10k i 3. kvartal 2026",
            Some(Lang::Da),
            &f.schema,
            &f.lex,
            &none(),
        )
        .unwrap(),
    );
    assert_eq!(d.text, "over :p1 i :p2");
    assert_eq!(d.params[0].ty, ParamType::Amount);
    assert_eq!(d.params[0].bound, Some(Bound::Amount(dec("10000"))));
    assert_eq!(d.params[1].ty, ParamType::DateRange);
    assert_eq!(
        d.params[1].bound,
        Some(Bound::DateRange("2026-07-01".into(), "2026-10-01".into()))
    );
    assert_eq!(d.params[1].display, "3. kvartal 2026");
}

#[test]
fn bad_literal_refuses() {
    let f = fx();
    let q = "invoices from 31 February 2026";
    match refusal(run(&f, q, &none())) {
        Refusal::BadLiteral { span, .. } => assert!(span.0 < span.1 && span.1 <= q.len()),
        other => panic!("{other:?}"),
    }
}

#[test]
fn known_city_is_text_param() {
    let f = fx();
    let det = ListDetector::new(&[("Aarhus", SpanLabel::Location)]);
    let d = ready(run(&f, "customers in Aarhus", &det));
    assert_eq!(d.text, "customers in :p1");
    assert_eq!(
        d.params[0].ty,
        ParamType::Text {
            table: "customers".into(),
            column: "city".into()
        }
    );
    assert_eq!(d.params[0].bound, Some(Bound::Text("Aarhus".into())));
    assert_eq!(d.params[0].display, "Aarhus");
}

#[test]
fn unknown_city_stays_text() {
    let f = fx();
    let det = ListDetector::new(&[("Atlantis", SpanLabel::Location)]);
    let d = ready(run(&f, "customers in Atlantis", &det));
    assert_eq!(d.text, "customers in Atlantis");
    assert!(d.params.is_empty());
    assert!(d.pending.is_empty());
}

#[test]
fn org_span_overlapping_a_city_keeps_the_known_part_and_checks_the_rest() {
    let f = fx();
    // The detector marks "Aarhus Anna Berg" as one Person span: "Aarhus"
    // is claimed by the lexicon literal, "Anna Berg" by the entity; nothing
    // is left over.
    let det = ListDetector::new(&[("Aarhus Anna Berg", SpanLabel::Person)]);
    let d = ask(run(&f, "in Aarhus Anna Berg owes", &det));
    assert_eq!(d.text, "in :p1 :p2 owes");
    assert_eq!(d.pending.len(), 1);
    // A span partly over a literal: the rest ("Zed Zulu") is an unknown
    // Person, never silently dropped.
    let det = ListDetector::new(&[("2026 Zed Zulu", SpanLabel::Person)]);
    let d = ask(run(&f, "in 2026 Zed Zulu paid", &det));
    assert_eq!(d.text, "in :p1 Zed Zulu paid");
    match &d.pending[0] {
        Pending::KeepName { span, name } => {
            assert_eq!(name, "Zed Zulu");
            assert_eq!(&"in 2026 Zed Zulu paid"[span.0..span.1], "Zed Zulu");
        }
        other => panic!("{other:?}"),
    }
    // A Location remainder that is a known city becomes a text parameter.
    let det = ListDetector::new(&[("2026 Odense", SpanLabel::Location)]);
    let d = ready(run(&f, "in 2026 Odense", &det));
    assert_eq!(d.text, "in :p1 :p2");
    assert_eq!(d.params[1].bound, Some(Bound::Text("Odense".into())));
    // A detector span inside a literal is dropped.
    let det = ListDetector::new(&[("July", SpanLabel::Person)]);
    let d = ready(run(&f, "since 1 July 2026", &det));
    assert_eq!(d.text, "since :p1");
}

#[test]
fn several_pending_steps_in_question_order() {
    let f = fx();
    let det = ListDetector::new(&[("Zed Zulu", SpanLabel::Person)]);
    let d = ask(run(&f, "Did Anna Berg pay Zed Zulu over 500?", &det));
    assert_eq!(d.text, "Did :p1 pay Zed Zulu over :p2?");
    assert_eq!(d.pending.len(), 2);
    assert!(matches!(d.pending[0], Pending::Pick { .. }));
    let d = ask(answer(d, Answer::Pick(1), &f.lex).unwrap());
    assert_eq!(d.pending.len(), 1);
    assert!(matches!(d.pending[0], Pending::KeepName { .. }));
    let d = ready(answer(d, Answer::KeepName(true), &f.lex).unwrap());
    assert_eq!(d.text, "Did :p1 pay Zed Zulu over :p2?");
    // A bare number is an integer (T1); "10 000" above is an amount.
    assert_eq!(d.params[1].bound, Some(Bound::Integer(500)));
}

struct Failing(bool);
impl NameDetector for Failing {
    fn detect(&self, _: &str) -> Result<Vec<NameSpan>, DetectError> {
        if self.0 {
            Err(DetectError::Unavailable(
                "model at /secret/Anna Berg missing".into(),
            ))
        } else {
            Err(DetectError::Failed)
        }
    }
}

#[test]
fn detector_error_refuses() {
    let f = fx();
    for det in [Failing(true), Failing(false)] {
        match refusal(run(&f, "What does Søren Ærø owe?", &det)) {
            Refusal::Detector(why) => {
                assert!(!why.contains("Anna") && !why.contains("secret"), "{why}");
            }
            other => panic!("{other:?}"),
        }
    }
}

/// Returns the spans it was built with, whatever the text.
struct Fixed(Vec<(usize, usize)>);
impl NameDetector for Fixed {
    fn detect(&self, _: &str) -> Result<Vec<NameSpan>, DetectError> {
        Ok(self
            .0
            .iter()
            .map(|&(start, end)| NameSpan {
                start,
                end,
                label: SpanLabel::Person,
            })
            .collect())
    }
}

#[test]
fn bad_detector_spans_refuse() {
    let f = fx();
    let q = "Hvad skylder Søren Ærø?"; // ø at 14..16
    for spans in [
        vec![(15, 20)],         // starts inside ø
        vec![(13, 15)],         // ends inside ø
        vec![(13, 999)],        // out of range
        vec![(20, 13)],         // reversed
        vec![(5, 5)],           // empty
        vec![(0, 12), (5, 20)], // overlapping
        vec![(usize::MAX, 3)],  // nonsense
        vec![(3, usize::MAX)],  // nonsense
    ] {
        match refusal(run(&f, q, &Fixed(spans.clone()))) {
            Refusal::Detector(_) => {}
            other => panic!("{spans:?}: {other:?}"),
        }
    }
}

#[test]
fn case_folding_never_shifts_offsets() {
    // İ, the Kelvin sign and ß change length when folded; the spans must
    // still point into the original.
    let f = fx();
    let q = "İİİ \u{212A}\u{212A} straße søren ærø, SØREN ÆRØ? ẞ";
    let d = ready(run(&f, q, &none()));
    assert_eq!(d.text, "İİİ \u{212A}\u{212A} straße :p1, :p2? ẞ");
    assert_eq!(d.original, q);
    let q = "Ze\u{301}lie İstanbul Anna Berg";
    let det = ListDetector::new(&[("Ze\u{301}lie İstanbul", SpanLabel::Person)]);
    let d = ask(run(&f, q, &det));
    assert_eq!(d.text, "Ze\u{301}lie İstanbul :p1");
    assert!(
        matches!(&d.pending[0], Pending::KeepName { name, .. } if name == "Ze\u{301}lie İstanbul")
    );
}

#[test]
fn template_key_matches_across_names() {
    let f = fx();
    let a = ask(run(&f, "What  does Anna Berg owe?", &none()));
    let a = ready(answer(a, Answer::Pick(1), &f.lex).unwrap());
    let s = ready(run(&f, "what does Søren Ærø owe", &none()));
    let (ka, ta) = template_key(&a);
    let (ks, ts) = template_key(&s);
    assert_eq!(ka, "what does :p1 owe");
    assert_eq!(ka, ks);
    assert_eq!(ta, vec!["entity:customers".to_string()]);
    assert_eq!(ta, ts);
}

#[test]
fn debug_hides_names_and_text() {
    let f = fx();
    let det = ListDetector::new(&[
        ("Zed Zulu", SpanLabel::Person),
        ("Ana Berg", SpanLabel::Person),
    ]);
    let d = ask(run(&f, "Did Anna Berg pay Zed Zulu 500?", &det));
    let ready_d = ready(run(&f, "What does Søren Ærø owe in Aarhus?", &none()));
    let typo = ask(run(&f, "What does Ana Berg owe?", &det));
    let keep = ask(answer(typo.clone(), Answer::DidYouMean(false), &f.lex).unwrap());
    let refused = answer(keep.clone(), Answer::KeepName(false), &f.lex).unwrap();
    let nomatch = answer(d.clone(), Answer::Pick(0), &f.lex).unwrap();
    let texts = [
        format!("{d:?}"),
        format!("{:?}", Step::Ask(d.clone())),
        format!("{ready_d:?}"),
        format!("{typo:?}"),
        format!("{keep:?}"),
        format!("{refused:?}"),
        format!("{nomatch:?}"),
        format!("{:?}", d.pending),
        format!("{:?}", typo.pending),
        format!("{:?}", Answer::Pick(1)),
    ];
    for t in &texts {
        for bad in [
            "Anna", "Berg", "Zed", "Zulu", "Søren", "Ærø", "Aarhus", "Odense", "500", "Ana",
        ] {
            assert!(!t.contains(bad), "{bad} in {t}");
        }
    }
    assert!(texts[0].contains("Pick"), "{}", texts[0]);
}

// ------------------------------------------------- never panics (S-1) ----

const PIECES: &[&str] = &[
    "Anna Berg",
    "søren ærø",
    "SØREN ÆRØ",
    "Mette Hansen",
    "Aarhus",
    "Ærøskøbing",
    "İ",
    "\u{212A}",
    "ß",
    "ẞ",
    "e\u{301}",
    "\u{301}",
    "A\u{30a}",
    "שלום",
    "مرحبا",
    "\u{202E}",
    "😀",
    "👩‍👩‍👧",
    "10 000",
    "10.000,50",
    "15k",
    "kr. 500",
    "500 NOK",
    "3%",
    "2026-07-01",
    "1. juli 2026",
    "Q3 2026",
    "3. kvartal 2026",
    "twenty-one",
    "enogtyve",
    "tre",
    "three",
    "١٢٣",
    "½",
    "５",
    " ",
    "  ",
    ",",
    "?",
    "-",
    "'",
    "\t",
    "\n",
    "what does",
    "hvad skylder",
    "owe",
    "over",
    "Zed Zulu",
    "Ana Berg",
    "B2B",
    "address2",
    "abc12",
    "12abc",
    "10,000",
    "1.500",
    "$5abc",
    "-500",
];

fn random_question(r: &mut Rng) -> String {
    let n = 1 + r.below(10) as usize;
    let mut s = String::new();
    for _ in 0..n {
        s.push_str(r.pick(PIECES));
        if r.below(3) > 0 {
            s.push(' ');
        }
    }
    s
}

/// Random spans: in range or not, on boundaries or not, overlapping or not.
struct Chaos(std::sync::Mutex<Rng>);
impl NameDetector for Chaos {
    fn detect(&self, text: &str) -> Result<Vec<NameSpan>, DetectError> {
        let mut r = self.0.lock().unwrap();
        if r.below(20) == 0 {
            return Err(DetectError::Failed);
        }
        let n = r.below(4) as usize;
        let lim = text.len() as u64 + 4;
        let labels = [
            SpanLabel::Person,
            SpanLabel::Org,
            SpanLabel::Location,
            SpanLabel::Misc,
        ];
        Ok((0..n)
            .map(|_| {
                let a = r.below(lim) as usize;
                let b = a + r.below(lim) as usize;
                NameSpan {
                    start: a,
                    end: b,
                    label: labels[r.below(4) as usize],
                }
            })
            .collect())
    }
}

/// Spans of whole tokens only, on boundaries, sometimes overlapping a
/// literal or an entity.
struct Words(std::sync::Mutex<Rng>);
impl NameDetector for Words {
    fn detect(&self, text: &str) -> Result<Vec<NameSpan>, DetectError> {
        let mut r = self.0.lock().unwrap();
        let mut out = Vec::new();
        let mut at = 0;
        for w in text.split(' ') {
            let start = at;
            at += w.len() + 1;
            if !w.is_empty() && r.below(3) == 0 {
                out.push(NameSpan {
                    start,
                    end: start + w.len(),
                    label: if r.below(2) == 0 {
                        SpanLabel::Person
                    } else {
                        SpanLabel::Location
                    },
                });
            }
        }
        Ok(out)
    }
}

/// Outcomes of the generated questions, so an all-`Err` regression fails.
#[derive(Default, Debug)]
struct Tally {
    parsed: usize,
    asked: usize,
    answered_ready: usize,
}

fn check(step: Result<Step, saiife_shield::ShieldError>, f: &Fx, r: &mut Rng, t: &mut Tally) {
    let Ok(mut step) = step else { return };
    if !matches!(step, Step::Refuse(_)) {
        t.parsed += 1;
    }
    if matches!(step, Step::Ask(_)) {
        t.asked += 1;
    }
    let mut answered = false;
    // Walk the answers to the end: every step is Ok or Err, never a panic.
    for _ in 0..8 {
        let d = match step {
            Step::Ask(d) => d,
            Step::Ready(d) => {
                let (k, _) = template_key(&d);
                assert!(!k.ends_with('?'));
                for (i, p) in d.params.iter().enumerate() {
                    assert_eq!(p.name, format!("p{}", i + 1));
                    assert!(p.bound.is_some());
                    assert!(d.text.contains(&format!(":{}", p.name)));
                }
                if answered {
                    t.answered_ready += 1;
                }
                return;
            }
            Step::Refuse(_) => return,
        };
        let (a, past_list) = match &d.pending[0] {
            Pending::Pick { candidates, .. } => {
                let n = r.below(candidates.len() as u64 + 2) as usize;
                (Answer::Pick(n), n > candidates.len())
            }
            Pending::DidYouMean { .. } => (Answer::DidYouMean(r.below(2) == 0), false),
            Pending::KeepName { .. } => (Answer::KeepName(r.below(2) == 0), false),
        };
        answered = true;
        match answer(d, a, &f.lex) {
            Ok(s) => step = s,
            // Only a pick past the list is a caller error here: a draft
            // made by `parameterize` always answers.
            Err(e) => {
                assert!(past_list, "{a:?}: {e}");
                return;
            }
        }
    }
}

#[test]
fn never_panics_on_arbitrary_text() {
    let f = fx();
    let mut r = Rng::new(0x5EED_0044);
    let chaos = Chaos(std::sync::Mutex::new(Rng::new(7)));
    let words = Words(std::sync::Mutex::new(Rng::new(11)));
    let list = ListDetector::new(&[
        ("Zed Zulu", SpanLabel::Person),
        ("Ana Berg", SpanLabel::Person),
        ("Aarhus", SpanLabel::Location),
        ("İ", SpanLabel::Misc),
        ("ß", SpanLabel::Org),
    ]);
    let mut t = Tally::default();
    for i in 0..600 {
        let q = random_question(&mut r);
        let lang = match i % 3 {
            0 => None,
            1 => Some(Lang::En),
            _ => Some(Lang::Da),
        };
        let det: &dyn NameDetector = match i % 3 {
            0 => &chaos,
            1 => &words,
            _ => &list,
        };
        let step = parameterize(&q, lang, &f.schema, &f.lex, det);
        check(step, &f, &mut r, &mut t);
    }
    // Raw random code points, including lone combining marks and controls.
    for _ in 0..200 {
        let n = r.below(24) as usize;
        let q: String = (0..n)
            .filter_map(|_| char::from_u32(r.below(0x3_0000) as u32))
            .collect();
        let step = parameterize(&q, None, &f.schema, &f.lex, &chaos);
        check(step, &f, &mut r, &mut t);
    }
    // A floor: most generated questions parse, many ask, and answers lead
    // to Ready drafts. (Random pieces often put two literals side by side
    // or beside a period word, which the split-meaning rules refuse.)
    assert!(
        t.parsed >= 250 && t.asked >= 50 && t.answered_ready >= 20,
        "{t:?}"
    );
}

// ------------------------------------------- Draft is public data (P-16) ----

#[test]
fn typed_param_token_refuses() {
    let f = fx();
    for (q, tok) in [
        ("What does :p9 owe?", ":p9"),
        ("What does Søren Ærø owe :P1", ":P1"),
        ("x:p12y", ":p12"),
    ] {
        match refusal(run(&f, q, &none())) {
            Refusal::BadLiteral { span, .. } => assert_eq!(&q[span.0..span.1], tok),
            other => panic!("{q}: {other:?}"),
        }
    }
    // `:p` without a digit after it is fine.
    let d = ready(run(&f, "ratio :p and :pa", &none()));
    assert_eq!(d.text, "ratio :p and :pa");
}

#[test]
fn did_you_mean_no_renumbers_and_maps_the_span() {
    let f = fx();
    let det = ListDetector::new(&[("Ana Berg", SpanLabel::Person)]);
    // A bound entity before the typo (its written text is not in the draft)
    // and an integer after it.
    let q = "Søren Ærø paid Ana Berg 500 and Ana Berg";
    let d = ask(run(&f, q, &det));
    assert_eq!(d.text, ":p1 paid :p2 :p3 and :p4");
    let d = ask(answer(d, Answer::DidYouMean(false), &f.lex).unwrap());
    assert_eq!(d.text, ":p1 paid Ana Berg :p2 and :p3");
    let names: Vec<&str> = d.params.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, vec!["p1", "p2", "p3"]);
    assert_eq!(d.params[1].bound, Some(Bound::Integer(500)));
    match &d.pending[0] {
        Pending::KeepName { span, name } => {
            assert_eq!(name, "Ana Berg");
            let at = q.find("Ana Berg").unwrap();
            assert_eq!(*span, (at, at + 8));
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(&d.pending[1], Pending::DidYouMean { param, .. } if param == "p3"));
    let d = ask(answer(d, Answer::KeepName(true), &f.lex).unwrap());
    let d = ask(answer(d, Answer::DidYouMean(false), &f.lex).unwrap());
    assert_eq!(d.text, ":p1 paid Ana Berg :p2 and Ana Berg");
    match &d.pending[0] {
        Pending::KeepName { span, .. } => assert_eq!(*span, (q.len() - 8, q.len())),
        other => panic!("{other:?}"),
    }
    let d = ready(answer(d, Answer::KeepName(true), &f.lex).unwrap());
    assert_eq!(d.params.len(), 2);
}

/// A later task builds a draft as a struct literal and answers it.
#[test]
fn hand_made_draft_answers() {
    use saiife_shield::lexicon::Candidate;
    use saiife_shield::schema::Param;
    let f = fx();
    let anna = |key: i64, city: &str| Candidate {
        key,
        table: "customers".into(),
        display: "Anna Berg".into(),
        show: vec![("city".into(), city.into())],
    };
    let d = Draft {
        lang: Lang::En,
        original: "Anna Berg over 10".into(),
        text: ":p1 over :p2".into(),
        params: vec![
            Param {
                name: "p1".into(),
                ty: customers(),
                bound: None,
                display: "Anna Berg".into(),
            },
            Param {
                name: "p2".into(),
                ty: ParamType::Integer,
                bound: Some(Bound::Integer(10)),
                display: "10".into(),
            },
        ],
        pending: vec![Pending::Pick {
            param: "p1".into(),
            word: "customer".into(),
            candidates: vec![anna(1, "Aarhus"), anna(2, "Odense")],
            too_many: false,
        }],
    };
    assert_eq!(
        template_key(&d),
        (
            ":p1 over :p2".to_string(),
            vec!["entity:customers".to_string(), "integer".to_string()]
        )
    );
    let r = ready(answer(d.clone(), Answer::Pick(2), &f.lex).unwrap());
    assert_eq!(r.params[0].bound, Some(Bound::Keys(vec![2])));
    assert_eq!(r.params[0].display, "Anna Berg, Odense (customer #2)");

    // Inconsistent drafts are errors, never panics.
    let mut bad: Vec<Draft> = Vec::new();
    let mut x = d.clone();
    x.text = ":p1 over 10".into(); // :p2 missing
    bad.push(x);
    let mut x = d.clone();
    x.text = ":p2 over :p1".into(); // out of order
    bad.push(x);
    let mut x = d.clone();
    x.text = ":p1 over :p2 :p3".into(); // extra
    bad.push(x);
    let mut x = d.clone();
    x.text = ":P1 over :p2".into();
    bad.push(x);
    let mut x = d.clone();
    x.text = ":p01 over :p2".into();
    bad.push(x);
    let mut x = d.clone();
    x.params[1].name = "p7".into();
    bad.push(x);
    let mut x = d.clone();
    x.params[0].bound = Some(Bound::Keys(vec![1])); // pending names a bound param
    bad.push(x);
    let mut x = d.clone();
    x.pending.clear(); // an unbound param nobody asks about
    x.pending.push(Pending::KeepName {
        span: (0, 4),
        name: "Anna".into(),
    });
    bad.push(x);
    let mut x = d.clone();
    if let Pending::Pick { param, .. } = &mut x.pending[0] {
        *param = "p9".into();
    }
    bad.push(x);
    let mut x = d.clone();
    x.pending.push(Pending::KeepName {
        span: (1, 99),
        name: "nna".into(),
    });
    bad.push(x);
    let mut x = d.clone();
    x.pending.push(Pending::KeepName {
        span: (0, 4),
        name: "Zed".into(),
    });
    bad.push(x);
    for (i, x) in bad.into_iter().enumerate() {
        assert!(answer(x, Answer::Pick(1), &f.lex).is_err(), "case {i}");
    }

    // DidYouMean "no" on a hand-made draft: the name goes back, mapped
    // through the verbatim text around the parameters.
    let d = Draft {
        lang: Lang::En,
        original: "10 to Ana Berg, 10".into(),
        text: ":p1 to :p2, :p3".into(),
        params: vec![
            Param {
                name: "p1".into(),
                ty: ParamType::Integer,
                bound: Some(Bound::Integer(10)),
                display: "10".into(),
            },
            Param {
                name: "p2".into(),
                ty: customers(),
                bound: None,
                display: "Ana Berg".into(),
            },
            Param {
                name: "p3".into(),
                ty: ParamType::Integer,
                bound: Some(Bound::Integer(10)),
                display: "10".into(),
            },
        ],
        pending: vec![Pending::DidYouMean {
            param: "p2".into(),
            word: "customer".into(),
            written: "Ana Berg".into(),
            suggestion: anna(1, "Aarhus"),
        }],
    };
    let k = ask(answer(d.clone(), Answer::DidYouMean(false), &f.lex).unwrap());
    assert_eq!(k.text, ":p1 to Ana Berg, :p2");
    assert!(matches!(&k.pending[0], Pending::KeepName { span, .. } if *span == (6, 14)));
    // A written name that is not in the original cannot be put back.
    let mut x = d.clone();
    if let Pending::DidYouMean { written, .. } = &mut x.pending[0] {
        *written = "Zed Zulu".into();
    }
    assert!(answer(x, Answer::DidYouMean(false), &f.lex).is_err());
    // A suggestion from another table than the param's type.
    let mut x = d;
    x.params[1].ty = ParamType::Entity {
        table: "orders".into(),
        word: "order".into(),
    };
    assert!(answer(x, Answer::DidYouMean(true), &f.lex).is_err());
}

// ---------------------------------------- final review fix wave (I1, I3) ----

#[test]
fn danish_name_in_english_question_never_binds_ten() {
    // Ruling P-27: function words decide (English), and `10,000` with an
    // auto-detected language is ambiguous: refused, never Amount 10.
    let f = fx();
    let q = "What does Søren Ærø owe, and is it over 10,000?";
    match refusal(run(&f, q, &none())) {
        Refusal::BadLiteral { span, why } => {
            assert_eq!(&q[span.0..span.1], "10,000");
            assert_eq!(why, saiife_shield::lang::AMBIGUOUS_NUMBER);
        }
        other => panic!("{other:?}"),
    }
    // An explicit language keeps today's reading.
    let d = ready(parameterize(q, Some(Lang::Da), &f.schema, &f.lex, &none()).unwrap());
    assert_eq!(d.lang, Lang::Da);
    assert_eq!(d.params[1].bound, Some(Bound::Amount(dec("10.000"))));
    let d = ready(parameterize(q, Some(Lang::En), &f.schema, &f.lex, &none()).unwrap());
    assert_eq!(d.params[1].bound, Some(Bound::Amount(dec("10000"))));
    // Two separators are not ambiguous.
    let d = ready(run(&f, "What does Søren Ærø owe over 10.000,50?", &none()));
    assert_eq!(d.lang, Lang::En);
    assert_eq!(d.params[1].bound, Some(Bound::Amount(dec("10000.50"))));
    // A Danish question with the same name stays Danish.
    let d = ready(run(&f, "hvad skylder søren ærø", &none()));
    assert_eq!(d.lang, Lang::Da);
}

#[test]
fn digits_glued_to_words_stay_text() {
    // Ruling P-29.
    let f = fx();
    let d = ready(run(&f, "customers with an empty address2", &none()));
    assert_eq!(d.text, "customers with an empty address2");
    assert!(d.params.is_empty());
    for q in ["customers in abc12", "customers in 12abc", "weight 15kg"] {
        let d = ready(run(&f, q, &none()));
        assert_eq!(d.text, q);
        assert!(d.params.is_empty(), "{q}");
    }
    // A public value with a digit is a text parameter, not `B:p1B`.
    let det = ListDetector::new(&[("B2B", SpanLabel::Misc)]);
    let d = ready(run(&f, "customers in segment B2B", &det));
    assert_eq!(d.text, "customers in segment :p1");
    assert_eq!(
        d.params[0].ty,
        ParamType::Text {
            table: "customers".into(),
            column: "segment".into()
        }
    );
    assert_eq!(d.params[0].bound, Some(Bound::Text("B2B".into())));
    // The allowed suffixes still make literals.
    let d = ready(run(&f, "over 15k on the 3rd", &none()));
    assert_eq!(d.text, "over :p1 on the :p2");
}

#[test]
fn minus_sign_stays_in_the_text() {
    let f = fx();
    let d = ready(run(&f, "balance under -500", &none()));
    assert_eq!(d.text, "balance under -:p1");
    assert_eq!(d.params[0].ty, ParamType::Integer);
    assert_eq!(d.params[0].bound, Some(Bound::Integer(500)));
}

// ------------------------------- plan 44 follow-up: bench item 1 (meaning) ----

use saiife_shield::question::{DECOMPOSED, ONE_SCALE_TWO_NUMBERS, SIDE_BY_SIDE, UNBOUND_WORD};

/// The closed word list the parameterizer must never leave beside a `:pN`
/// (with `of`/`af`/`the` skipped): a period, an ordinal, a fraction or a
/// scale word. A copy, so the test does not trust the code's own list.
const SPLIT_WORDS: &[&str] = &[
    "quarter",
    "quarters",
    "kvartal",
    "kvartaler",
    "kvartalet",
    "half",
    "halves",
    "halvår",
    "halvåret",
    "halvdel",
    "halvdelen",
    "semester",
    "h1",
    "h2",
    "q1",
    "q2",
    "q3",
    "q4",
    "first",
    "second",
    "third",
    "fourth",
    "første",
    "anden",
    "andet",
    "tredje",
    "fjerde",
    "halv",
    "halvanden",
    "kvart",
    "hundred",
    "thousand",
    "thousands",
    "million",
    "millions",
    "billion",
    "hundrede",
    "tusind",
    "tusinde",
    "millioner",
    "milliard",
    "milliarder",
    "mio",
    "mia",
    "bn",
    "mn",
    "k",
    "dozen",
    "dusin",
];

/// True when a split word sits beside a parameter in `text`.
fn split_beside_param(text: &str) -> bool {
    let toks: Vec<String> = text
        .split(|c: char| !(c.is_alphanumeric() || c == ':'))
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .filter(|w| !matches!(w.as_str(), "of" | "af" | "the"))
        .collect();
    toks.windows(2).any(|w| {
        let p = |s: &str| s.starts_with(":p");
        (p(&w[0]) && SPLIT_WORDS.contains(&w[1].as_str()))
            || (p(&w[1]) && SPLIT_WORDS.contains(&w[0].as_str()))
            || (p(&w[0]) && p(&w[1]))
    })
}

fn bad_literal_why(s: Step) -> &'static str {
    match refusal(s) {
        Refusal::BadLiteral { why, .. } => why,
        other => panic!("expected BadLiteral, got {other:?}"),
    }
}

/// The bench's three WRONG answers (naive planner), en and da: each binds
/// as one parameter of the right value.
#[test]
fn bench_cases_bind_as_one_parameter() {
    let f = fx();
    let h1 = Bound::DateRange("2024-01-01".into(), "2024-07-01".into());
    let q2 = Bound::DateRange("2025-04-01".into(), "2025-07-01".into());
    let cases: [(&str, &str, ParamType, &Bound); 8] = [
        (
            "Hvad var omsætningen i første halvår 2024?",
            "Hvad var omsætningen i :p1?",
            ParamType::DateRange,
            &h1,
        ),
        (
            "What was the revenue in the first half of 2024?",
            "What was the revenue in the :p1?",
            ParamType::DateRange,
            &h1,
        ),
        (
            "What was the revenue in H1 2024?",
            "What was the revenue in :p1?",
            ParamType::DateRange,
            &h1,
        ),
        (
            "What was the revenue in the second quarter of 2025?",
            "What was the revenue in the :p1?",
            ParamType::DateRange,
            &q2,
        ),
        (
            "Hvad var omsætningen i andet kvartal 2025?",
            "Hvad var omsætningen i :p1?",
            ParamType::DateRange,
            &q2,
        ),
        (
            "Hvad var omsætningen i 2025 Q2?",
            "Hvad var omsætningen i :p1?",
            ParamType::DateRange,
            &q2,
        ),
        (
            "How many invoices are over 1,5 thousand?",
            "How many invoices are over :p1?",
            ParamType::Amount,
            &Bound::Amount(dec("1500")),
        ),
        (
            "Hvor mange fakturaer er over 1,5 tusind kr.?",
            "Hvor mange fakturaer er over :p1?",
            ParamType::Amount,
            &Bound::Amount(dec("1500")),
        ),
    ];
    for (q, text, ty, bound) in cases {
        let d = ready(run(&f, q, &none()));
        assert_eq!(d.text, text, "{q}");
        assert_eq!(d.params.len(), 1, "{q}");
        assert_eq!(d.params[0].ty, ty, "{q}");
        assert_eq!(d.params[0].bound.as_ref(), Some(bound), "{q}");
        assert!(!split_beside_param(&d.text), "{q}");
    }
}

/// Fail closed: a period, ordinal, fraction or scale word the literal does
/// not cover, beside a parameter, refuses the question.
#[test]
fn an_unbound_period_ordinal_or_scale_word_refuses() {
    let f = fx();
    for q in [
        // An ordinal period with no year: `:p1 halvår`, `the :p1 quarter`.
        "Hvad var omsætningen i første halvår?",
        "Hvad var omsætningen i 1. halvår?",
        "What was the revenue in the second quarter?",
        "Hvad var omsætningen i andet kvartal?",
        // A year beside a period it does not cover.
        "What was the revenue in the last quarter of 2024?",
        "What was the revenue per quarter 2024?",
        "What was the revenue in Q1-Q2 2024?",
        // A fraction beside a scale: `half :p1` (= a million).
        "Which customers owe more than half a million?",
        // A scale word the language does not read (Danish billion = 10^12).
        "Hvilke kunder skylder mere end 2 billioner kr.?",
        "Which customers owe more than 2 bn?",
    ] {
        assert_eq!(bad_literal_why(run(&f, q, &none())), UNBOUND_WORD, "{q}");
    }
    // A detected language that does not read the ordinal: `første` stays
    // text beside the year (fail closed, never a whole-year range).
    let q = "første halvår 2024";
    let s = parameterize(q, Some(Lang::En), &f.schema, &f.lex, &none()).unwrap();
    assert_eq!(bad_literal_why(s), UNBOUND_WORD);
}

#[test]
fn numbers_side_by_side_refuse() {
    let f = fx();
    for q in [
        "Show the first 10 customers",
        "What was the revenue in 2023/2024?",
        "Who has number 010203-4560?",
        "Hvad var omsætningen i uge 12 2024?",
    ] {
        assert_eq!(bad_literal_why(run(&f, q, &none())), SIDE_BY_SIDE, "{q}");
    }
    for q in [
        "Which customers owe between 1 and 2 million?",
        "Hvilke kunder skylder mellem 1 og 2 millioner kr.?",
        "Which customers owe 1 to 2 thousand?",
    ] {
        assert_eq!(
            bad_literal_why(run(&f, q, &none())),
            ONE_SCALE_TWO_NUMBERS,
            "{q}"
        );
    }
}

/// What must keep working: numbers next to ordinary words, lists, ranges
/// with both ends written out.
#[test]
fn ordinary_numbers_still_bind() {
    let f = fx();
    for (q, text) in [
        (
            "Which customers owe between 1 million and 2 million?",
            "Which customers owe between :p1 and :p2?",
        ),
        (
            "What was the revenue in the last 3 months?",
            "What was the revenue in the last :p1 months?",
        ),
        (
            "What was the revenue in 2023, 2024 and 2025?",
            "What was the revenue in :p1, :p2 and :p3?",
        ),
        (
            "Hvad var omsætningen i 3. kvartal 2026?",
            "Hvad var omsætningen i :p1?",
        ),
        (
            "What was the revenue per quarter in 2024?",
            "What was the revenue per quarter in :p1?",
        ),
        (
            "Which customers owe more than 10 000 in 2024?",
            "Which customers owe more than :p1 in :p2?",
        ),
    ] {
        let d = ready(run(&f, q, &none()));
        assert_eq!(d.text, text, "{q}");
    }
}

/// The property, over many phrasings: a draft never holds a split word or
/// a second number beside a `:pN`; it binds or it refuses.
#[test]
fn never_a_split_over_phrasings() {
    let f = fx();
    let periods = [
        "første halvår 2024",
        "første halvår",
        "andet halvår af 2024",
        "2. halvår 2024",
        "first half of 2024",
        "the first half 2024",
        "second half",
        "H1 2024",
        "2024 H2",
        "the second quarter of 2025",
        "second quarter",
        "andet kvartal 2025",
        "fjerde kvartal",
        "Q2 of 2025",
        "2025 Q1",
        "2025 Q1 2026",
        "last quarter of 2024",
        "1,5 thousand",
        "1,5 tusind",
        "2 million",
        "2 millioner kr.",
        "half a million",
        "en halv million",
        "1 and 2 million",
        "a quarter of a million",
        "2 billion",
        "tre kvart million",
        "the first 10",
    ];
    for p in periods {
        for q in [
            format!("What was the revenue in {p}?"),
            format!("Hvad var omsætningen i {p}?"),
            format!("Which customers owe more than {p}?"),
        ] {
            match run(&f, &q, &none()) {
                Step::Ready(d) | Step::Ask(d) => {
                    assert!(!split_beside_param(&d.text), "{q} -> split");
                }
                Step::Refuse(_) => {}
            }
        }
    }
}

/// Review fixes (bench item 1): more ways a meaning could split, each
/// refused.
#[test]
fn review_split_cases_refuse() {
    let f = fx();
    for q in [
        // A period code, a filler word, then the year.
        "What was the revenue in Q2 in 2025?",
        "What was the revenue for H1 FY 2024?",
        // Month ranges.
        "What was the revenue in jan-mar 2024?",
        "What was the revenue from January to March 2024?",
        "Hvad var omsætningen fra 1. januar til 31. marts 2024?",
        // Two ordinals or codes sharing one period.
        "What was the revenue in the 1st and 2nd quarter 2025?",
        "Hvad var omsætningen i første og andet halvår 2024?",
        "What was the revenue in Q1 and Q2 2024?",
        // A number word of the other language beside a number.
        "Ørsted revenue over two 2024",
        // Brackets.
        "What was the revenue in H1 (2024)?",
        // Abbreviations and ordinal months.
        "Hvad var omsætningen i 2. kvt. 2024?",
        "What was the revenue in the 2nd qtr 2025?",
        "What was the revenue in the 3rd month of 2024?",
        "Hvilke kunder skylder over 2 bln?",
        // A bare scale word with a number word before it.
        "Which customers owe more than 3 dozen?",
        // A unit on one end of a range.
        "Which customers owe between 10 and 20 percent?",
        "Which customers owe 100 to 200 kr?",
    ] {
        match run(&f, q, &none()) {
            Step::Refuse(Refusal::BadLiteral { .. }) => {}
            Step::Ready(d) | Step::Ask(d) => panic!("{q} -> {:?}", d.params),
            other => panic!("{q} -> {other:?}"),
        }
    }
}

/// Review fixes: what binds instead of splitting.
#[test]
fn review_binding_cases() {
    let f = fx();
    // A decomposed å in `halvår` hides the period word: refused.
    assert_eq!(
        bad_literal_why(run(
            &f,
            "Hvad var omsætningen i første halva\u{30a}r 2024?",
            &none(),
        )),
        DECOMPOSED
    );
    // A bare scale word after a fraction is no number: nothing is split.
    for q in [
        "Hvilke kunder skylder mere end en halv million?",
        "Hvilke kunder skylder mere end halvanden million?",
    ] {
        assert!(ready(run(&f, q, &none())).params.is_empty(), "{q}");
    }
    // A number word the detected language does not read is no parameter
    // (`two` beside a bare `million`): nothing is split.
    let d = ready(run(&f, "Ørsted revenue over two million", &none()));
    assert!(d.params.is_empty());
    // `2 mill. kr.` and `2 mln` are one amount.
    let d = ready(run(&f, "Which customers owe over 2 mln?", &none()));
    assert_eq!(d.params[0].bound, Some(Bound::Amount(dec("2000000"))));
    let d = ready(run(&f, "Hvilke kunder skylder over 2 mill. kr.?", &none()));
    assert_eq!(d.text, "Hvilke kunder skylder over :p1?");
    assert_eq!(d.params[0].bound, Some(Bound::Amount(dec("2000000"))));
    // A bare scale word is not a number: no parameter.
    let d = ready(run(
        &f,
        "Hvilke kunder skylder flere millioner kr.?",
        &none(),
    ));
    assert!(d.params.is_empty());
    // A cardinal is not an ordinal: `one quarter of 2025` is not Q1.
    match run(&f, "What was one quarter of 2025 revenue?", &none()) {
        Step::Refuse(Refusal::BadLiteral { why, .. }) => assert_eq!(why, UNBOUND_WORD),
        other => panic!("{other:?}"),
    }
    // A plain count of months still binds.
    let d = ready(run(
        &f,
        "What was the revenue in the last 3 months?",
        &none(),
    ));
    assert_eq!(d.text, "What was the revenue in the last :p1 months?");
}
