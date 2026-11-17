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
                Cell::Text("retail".into()),
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
    // R44-1: an æ, ø or å makes the question Danish, names included.
    assert_eq!(d.lang, Lang::Da);
    assert_eq!(d.text, "What does :p1 owe, and is it over :p2?");
    assert_eq!(d.params.len(), 2);
    assert_eq!(d.params[0].name, "p1");
    assert_eq!(d.params[0].ty, customers());
    assert_eq!(d.params[0].bound, Some(Bound::Keys(vec![3])));
    assert_eq!(d.params[0].display, "Søren Ærø, Aalborg (kunde #3)");
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
            written,
            suggestion,
        } => {
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
        Refusal::BadLiteral { span } => assert!(span.0 < span.1 && span.1 <= q.len()),
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

fn check(step: Result<Step, saiife_shield::ShieldError>, f: &Fx, r: &mut Rng) {
    let Ok(mut step) = step else { return };
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
                return;
            }
            Step::Refuse(_) => return,
        };
        let a = match &d.pending[0] {
            Pending::Pick { candidates, .. } => {
                Answer::Pick(r.below(candidates.len() as u64 + 2) as usize)
            }
            Pending::DidYouMean { .. } => Answer::DidYouMean(r.below(2) == 0),
            Pending::KeepName { .. } => Answer::KeepName(r.below(2) == 0),
        };
        match answer(d, a, &f.lex) {
            Ok(s) => step = s,
            Err(_) => return,
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
        check(step, &f, &mut r);
    }
    // Raw random code points, including lone combining marks and controls.
    for _ in 0..200 {
        let n = r.below(24) as usize;
        let q: String = (0..n)
            .filter_map(|_| char::from_u32(r.below(0x3_0000) as u32))
            .collect();
        let step = parameterize(&q, None, &f.schema, &f.lex, &chaos);
        check(step, &f, &mut r);
    }
}
