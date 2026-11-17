//! Runs 1 000 generated questions through the parameterizer and the leak
//! firewall over a dataset built by `blind_build` (plan 44 T5):
//! `cargo run --release -p saiife-shield --example blind_firewall -- <dataset dir>`.
//!
//! Half the questions name a random fixture customer (by name, in English
//! or Danish, or by email); half are clean parameterized questions. Each
//! naming question must be resolved locally (sent only with a stand-in) or
//! blocked, and its raw text, sent as is, must be blocked. Prints the counts
//! and the p50/p99 time of `check_bytes` on the canonical bytes; exits 1 on a leak. For the
//! owner smoke (`scripts/blind-smoke.d/20-firewall.sh`). Prints counts and
//! times only, never a value.

use rusqlite::{Connection, OpenFlags};
use saiife_shield::dataset::{load_manifest, DatasetDir};
use saiife_shield::envelope::{
    build_envelope, cloud_schema, schema_sha256, synthetic_sha256, Envelope,
};
use saiife_shield::firewall::{Expected, Firewall, Verdict};
use saiife_shield::index::{read_allow, IndexKey, KnownIndex, ALLOW_FILE};
use saiife_shield::lexicon::Lexicon;
use saiife_shield::ner::{ListDetector, SpanLabel};
use saiife_shield::question::{parameterize, Draft, Step};
use saiife_shield::schema::{Bound, Lang, Param, ParamType};
use saiife_shield::session::Session;
use saiife_shield::standin::KeySet;
use saiife_shield::synth::{os_rng, synthetic_rows};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const QUESTIONS: usize = 1000;
const LIST_CAP: u32 = 50;

/// The fixed test key of `blind_build`: never use it for real data.
fn test_key() -> IndexKey {
    let s = concat!("blind-build-", "example-only-", "fixed-test-key");
    let mut k = [0u8; 32];
    for (d, b) in k.iter_mut().zip(s.bytes().cycle()) {
        *d = b;
    }
    IndexKey(Zeroizing::new(k))
}

fn fail(what: &str) -> ! {
    eprintln!("blind_firewall: {what}");
    std::process::exit(1);
}

struct Person {
    first: String,
    last: String,
    email: String,
}

fn pick_people(dir: &DatasetDir, n: usize) -> Vec<Person> {
    let conn = Connection::open_with_flags(dir.snapshot(), OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap_or_else(|_| fail("could not open the snapshot"));
    let rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM customers", [], |r| r.get(0))
        .unwrap_or_else(|_| fail("could not count the customers"));
    if rows < 1 {
        fail("the dataset has no customers");
    }
    let mut st = conn
        .prepare("SELECT first_name, last_name, email FROM customers WHERE id = ?1")
        .unwrap_or_else(|_| fail("could not read the customers"));
    let mut rng = os_rng();
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let id = 1 + (rng() % rows as u64) as i64;
        if let Ok(p) = st.query_row([id], |r| {
            Ok(Person {
                first: r.get(0)?,
                last: r.get(1)?,
                email: r.get(2)?,
            })
        }) {
            out.push(p);
        }
    }
    out
}

fn pct(sorted: &[Duration], p: usize) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let i = (sorted.len() * p).div_ceil(100).clamp(1, sorted.len()) - 1;
    sorted[i].as_secs_f64() * 1000.0
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [root] = args.as_slice() else {
        eprintln!("usage: blind_firewall <dataset dir>");
        std::process::exit(2);
    };
    let dir = DatasetDir {
        root: PathBuf::from(root),
    };
    let m = load_manifest(&dir).unwrap_or_else(|_| fail("could not load the dataset"));
    let schema = &m.schema;
    let index = KnownIndex::open(&dir.live(), test_key())
        .unwrap_or_else(|_| fail("could not open the index"));
    let allow = read_allow(&dir.live().join(ALLOW_FILE))
        .unwrap_or_else(|_| fail("could not read the allow list"));
    let lex = Lexicon::open(&dir.lexicon()).unwrap_or_else(|_| fail("could not open the lexicon"));
    let entity = schema
        .entity_for("customers")
        .unwrap_or_else(|| fail("customers is not an entity"))
        .clone();
    let keys = KeySet::generate("2026-11-17T00:00:00Z")
        .unwrap_or_else(|_| fail("could not make a key set"));
    let mut session = Session::new(1000, schema.dataset.clone(), &keys, 0)
        .unwrap_or_else(|_| fail("could not start a session"));

    let naming = QUESTIONS / 2;
    let people = pick_people(&dir, naming);
    // The stand-in for an NER model: it knows the picked names.
    let full: Vec<String> = people
        .iter()
        .map(|p| format!("{} {}", p.first, p.last))
        .collect();
    let entries: Vec<(&str, SpanLabel)> = full
        .iter()
        .map(|n| (n.as_str(), SpanLabel::Person))
        .collect();
    let det = ListDetector::new(&entries);
    // The scan runs on the final bytes (`check_bytes`, P-22) with what the
    // caller kept when it built the envelope (P-26): the list cap, the
    // language, the schema and synthetic hashes, and the stand-ins the
    // session issued (looked up in the session, P-25).
    let schema_hash = schema_sha256(&cloud_schema(schema, &m.public));
    let mut times: Vec<Duration> = Vec::with_capacity(QUESTIONS * 2);
    let mut scan = |e: &Envelope, hash: &str, lang: Lang, issued: &[String]| {
        let fw = Firewall {
            index: &index,
            allow: &allow,
            detector: &det,
            released_names: &[],
            expected: Expected {
                list_cap: LIST_CAP,
                lang,
                schema_sha256: &schema_hash,
                synthetic_sha256: hash,
                symbols: issued,
                previous_method_sha256: None,
            },
        };
        let bytes = e.canonical();
        let t0 = Instant::now();
        let v = fw
            .check_bytes(&bytes)
            .unwrap_or_else(|_| fail("the firewall failed"));
        times.push(t0.elapsed());
        v
    };
    let mut rng = os_rng();
    let mut envelope = |d: &Draft, s: &mut Session| {
        let synth = synthetic_rows(schema, &m.formats, &m.public, 5, &mut rng);
        let hash = synthetic_sha256(&synth);
        let e = build_envelope(d, s, schema, &m.public, synth, LIST_CAP, None);
        let issued: Vec<String> = e
            .params
            .iter()
            .filter_map(|p| p.symbol.clone())
            .filter(|sym| s.key_for_symbol(sym).is_some())
            .collect();
        (e, hash, issued)
    };
    let raw = |q: &str, lang: Lang| Draft {
        lang,
        original: q.to_string(),
        text: q.to_string(),
        params: vec![],
        pending: vec![],
    };

    let (mut sent, mut asked, mut refused, mut blocked) = (0usize, 0usize, 0usize, 0usize);
    let (mut probes_blocked, mut leaks) = (0usize, 0usize);
    for (i, p) in people.iter().enumerate() {
        let name = format!("{} {}", p.first, p.last);
        let (q, value) = match i % 3 {
            0 => (format!("What does {name} owe?"), name.clone()),
            1 => (format!("Hvad skylder {name}?"), name.clone()),
            _ => (
                format!("What is the credit limit of {}?", p.email),
                p.email.clone(),
            ),
        };
        let lang = saiife_shield::lang::detect_lang(&q);
        match parameterize(&q, None, schema, &lex, &det) {
            Ok(Step::Ready(d)) => {
                let (e, hash, issued) = envelope(&d, &mut session);
                match scan(&e, &hash, d.lang, &issued) {
                    Verdict::Pass => {
                        let bytes = e.canonical();
                        let text = String::from_utf8_lossy(&bytes);
                        if text.contains(&value) {
                            leaks += 1;
                        } else {
                            sent += 1;
                        }
                    }
                    Verdict::Block(_) => blocked += 1,
                }
            }
            Ok(Step::Ask(_)) => asked += 1,
            Ok(Step::Refuse(_)) | Err(_) => refused += 1,
        }
        // The raw question, as if the parameterizer had missed the name.
        let (e, hash, issued) = envelope(&raw(&q, lang), &mut session);
        match scan(&e, &hash, lang, &issued) {
            Verdict::Block(_) => probes_blocked += 1,
            Verdict::Pass => leaks += 1,
        }
    }

    let clean_q = [
        "What is the credit limit of :p1?",
        "How many invoices are overdue?",
        "Which segment has the most customers?",
        "Hvad er det samlede beløb for :p1?",
        "What is the average amount of the invoices of :p1?",
    ];
    let (mut passed, mut false_blocks) = (0usize, 0usize);
    for i in 0..(QUESTIONS - naming) {
        let q = clean_q[i % clean_q.len()];
        let lang = saiife_shield::lang::detect_lang(q);
        let mut d = raw(q, lang);
        if q.contains(":p1") {
            let key = 1 + (rng_key(i) % 1000) as i64;
            d.params.push(Param {
                name: "p1".into(),
                ty: ParamType::Entity {
                    table: "customers".into(),
                    word: entity.word.clone(),
                },
                bound: Some(Bound::Keys(vec![key])),
                display: String::new(),
            });
        }
        let (e, hash, issued) = envelope(&d, &mut session);
        match scan(&e, &hash, lang, &issued) {
            Verdict::Pass => passed += 1,
            Verdict::Block(_) => false_blocks += 1,
        }
    }

    times.sort_unstable();
    let unresolved = naming - (sent + asked + refused + blocked);
    println!(
        "questions {QUESTIONS} naming {naming} clean {}",
        QUESTIONS - naming
    );
    println!("naming sent_with_standin {sent} asked {asked} refused {refused} blocked {blocked}");
    println!("probes blocked {probes_blocked} of {naming}");
    println!("clean passed {passed} blocked {false_blocks}");
    println!("leaks {leaks}");
    println!("unresolved {unresolved}");
    println!(
        "scans {} p50_ms {:.2} p99_ms {:.2}",
        times.len(),
        pct(&times, 50),
        pct(&times, 99)
    );
    if leaks > 0 || probes_blocked != naming || unresolved != 0 {
        std::process::exit(1);
    }
}

/// A fixed spread of keys for the clean questions.
fn rng_key(i: usize) -> u64 {
    (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 11
}
