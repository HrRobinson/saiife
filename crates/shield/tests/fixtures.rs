//! The synthetic fixture generator (plan 43 T3). Shared by the tests
//! (`#[path = "fixtures.rs"] mod fixtures;`) and the `blind_fixture` example.
//! Every value is made up from a fixed seed: no real people, no real data.
#![allow(dead_code)]

use saiife_shield::dataset::Proposal;
use saiife_shield::schema::{ColumnClass, ColumnInfo, EntitySpec, Schema, TableInfo};
use saiife_shield::source::{CsvSource, RowIter, RowSource, SourceTable};
use saiife_shield::ShieldError;
use std::io;
use std::path::Path;

const FIRST: &[&str] = &[
    "Søren", "Åse", "Anna", "Mette", "Jens", "Lars", "Freja", "Mads", "Ida", "Niels", "Karen",
    "Emil", "Oliver", "Emma", "James", "Sophie", "Thomas", "Lucy",
];
const LAST: &[&str] = &[
    "Østergård",
    "Berg",
    "Ærø",
    "Jensen",
    "Nielsen",
    "Hansen",
    "Pedersen",
    "Andersen",
    "Larsen",
    "Møller",
    "Smith",
    "Taylor",
    "Brown",
    "Wilson",
];
const CITY: &[(&str, u32)] = &[
    ("København", 1050),
    ("Aarhus", 8000),
    ("Odense", 5000),
    ("Aalborg", 9000),
    ("Ærøskøbing", 5970),
    ("Esbjerg", 6700),
    ("London", 1001),
    ("Leeds", 2001),
];
const SEGMENT: &[&str] = &["retail", "business", "vip"];
const STATUS: &[&str] = &["paid", "open", "overdue"];
const NOTE: &[&str] = &[
    "",
    "",
    "paid by card",
    "reminder sent",
    "called {name} about the invoice",
    "{name} asked for a new due date",
    "delivered to {city}",
];

/// SplitMix64: small, fast, deterministic.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
    pub fn pick<'a>(&mut self, xs: &[&'a str]) -> &'a str {
        xs[self.below(xs.len() as u64) as usize]
    }
}

fn days_in(y: u32, m: u32) -> u32 {
    match m {
        2 if (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// A random (year, month, day) between `y0` and `y1` inclusive.
fn date(r: &mut Rng, y0: u32, y1: u32) -> (u32, u32, u32) {
    let y = y0 + r.below(u64::from(y1 - y0 + 1)) as u32;
    let m = 1 + r.below(12) as u32;
    let d = 1 + r.below(u64::from(days_in(y, m))) as u32;
    (y, m, d)
}

/// The modulus-11 check: weights 4,3,2,7,6,5,4,3,2,1 sum to a multiple of 11.
pub fn cpr_mod11_ok(code: &str) -> bool {
    let digits: Vec<u32> = code.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 10 || code.len() != 11 || code.as_bytes()[6] != b'-' {
        return false;
    }
    const W: [u32; 10] = [4, 3, 2, 7, 6, 5, 4, 3, 2, 1];
    digits.iter().zip(W).map(|(d, w)| d * w).sum::<u32>() % 11 == 0
}

/// A synthetic CPR-shaped `DDMMYY-SSSS` for a birth date, with a valid
/// modulus-11 check digit.
pub fn cpr_shaped(r: &mut Rng, (y, m, d): (u32, u32, u32)) -> String {
    const W: [u32; 9] = [4, 3, 2, 7, 6, 5, 4, 3, 2];
    loop {
        let seq = r.below(1000) as u32;
        let first9 = [
            d / 10,
            d % 10,
            m / 10,
            m % 10,
            (y / 10) % 10,
            y % 10,
            seq / 100,
            (seq / 10) % 10,
            seq % 10,
        ];
        let sum: u32 = first9.iter().zip(W).map(|(a, w)| a * w).sum();
        let check = (11 - sum % 11) % 11;
        if check == 10 {
            continue;
        }
        return format!("{d:02}{m:02}{:02}-{seq:03}{check}", y % 100);
    }
}

fn ascii_fold(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars().flat_map(char::to_lowercase) {
        match c {
            'æ' => o.push_str("ae"),
            'ø' => o.push_str("oe"),
            'å' => o.push_str("aa"),
            c if c.is_ascii_alphanumeric() => o.push(c),
            _ => {}
        }
    }
    o
}

/// Writes `customers.csv` (`rows` rows) and `invoices.csv` (2 x `rows` rows)
/// into `dir`.
pub fn write_fixture(dir: &Path, rows: u64, seed: u64) -> io::Result<()> {
    write_fixture_sized(dir, rows, rows.saturating_mul(2), seed)
}

/// Writes `customers.csv` (`rows` rows) and `invoices.csv` (`invoices` rows)
/// into `dir`.
pub fn write_fixture_sized(dir: &Path, rows: u64, invoices: u64, seed: u64) -> io::Result<()> {
    let mut r = Rng::new(seed);
    let mut cust = csv::Writer::from_path(dir.join("customers.csv"))?;
    cust.write_record([
        "id",
        "first_name",
        "last_name",
        "email",
        "phone",
        "city",
        "postcode",
        "birth_date",
        "segment",
        "credit_limit",
        "ref_code",
    ])?;
    let mut names = Vec::with_capacity(rows.min(1 << 20) as usize);
    for id in 1..=rows {
        let first = r.pick(FIRST);
        let last = r.pick(LAST);
        let (city, pc) = CITY[r.below(CITY.len() as u64) as usize];
        let born = date(&mut r, 1940, 2005);
        let email = format!(
            "{}.{}.{id}@example.invalid",
            ascii_fold(first),
            ascii_fold(last)
        );
        let phone = format!(
            // `+45 00`: no Danish number starts with 00, so these are fictional.
            "+45 00 {:02} {:02} {:02}",
            r.below(100),
            r.below(100),
            r.below(100)
        );
        let credit = format!("{}.{:02}", 1000 + r.below(99_000), r.below(100));
        let refc = cpr_shaped(&mut r, born);
        cust.write_record([
            id.to_string().as_str(),
            first,
            last,
            &email,
            &phone,
            city,
            &(pc + r.below(9) as u32).to_string(),
            &format!("{:04}-{:02}-{:02}", born.0, born.1, born.2),
            r.pick(SEGMENT),
            &credit,
            &refc,
        ])?;
        if names.len() < (1 << 20) {
            names.push((first, city));
        }
    }
    cust.flush()?;

    let mut inv = csv::Writer::from_path(dir.join("invoices.csv"))?;
    inv.write_record(["id", "customer_id", "amount", "status", "issued", "notes"])?;
    for id in 1..=invoices {
        let cid = 1 + r.below(rows.max(1));
        let (first, city) = names
            .get(((cid - 1) as usize).min(names.len().saturating_sub(1)))
            .copied()
            .unwrap_or(("Anna", "Aarhus"));
        let (y, m, d) = date(&mut r, 2022, 2025);
        let note = r
            .pick(NOTE)
            .replace("{name}", first)
            .replace("{city}", city);
        inv.write_record([
            id.to_string().as_str(),
            &cid.to_string(),
            &format!("{}.{:02}", r.below(50_000), r.below(100)),
            r.pick(STATUS),
            &format!("{y:04}-{m:02}-{d:02}"),
            &note,
        ])?;
    }
    inv.flush()?;
    Ok(())
}

/// Several sources read as one (the CSV files of a fixture dir): tables in
/// order, rows routed by table name.
pub struct MultiSource(pub Vec<Box<dyn RowSource>>);

impl MultiSource {
    /// Every `*.csv` in `dir`, sorted by name.
    pub fn csv_dir(dir: &Path) -> io::Result<MultiSource> {
        let mut files: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "csv"))
            .collect();
        files.sort();
        let mut v: Vec<Box<dyn RowSource>> = Vec::new();
        for p in files {
            let f = std::fs::File::open(&p)?;
            let name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            let s = CsvSource::open(Box::new(f), &name)
                .map_err(|_| io::Error::other("could not open a CSV"))?;
            v.push(Box::new(s));
        }
        Ok(MultiSource(v))
    }
}

impl RowSource for MultiSource {
    fn tables(&self) -> Vec<SourceTable> {
        self.0.iter().flat_map(|s| s.tables()).collect()
    }
    fn rows(&mut self, table: &str) -> Result<RowIter<'_>, ShieldError> {
        for s in &mut self.0 {
            if s.tables().iter().any(|t| t.name == table) {
                return s.rows(table);
            }
        }
        Err(ShieldError::Corrupt("no such table in the source"))
    }
    fn first_data_row(&self) -> u64 {
        self.0.first().map_or(1, |s| s.first_data_row())
    }
    fn set_spool_dir(&mut self, dir: &Path) {
        self.0.iter_mut().for_each(|s| s.set_spool_dir(dir));
    }
    fn release(&mut self) {
        self.0.iter_mut().for_each(|s| s.release());
    }
}

/// The schema of "accept every proposal": each column gets the suggested
/// class (a refused `public` suggestion becomes `sensitive`), and a table
/// with an `id` and name columns is an entity with the default words
/// `record` / `post`. Row counts are 0: `finish` fills them in.
pub fn accept_all(name: &str, props: &[Proposal]) -> Schema {
    let mut tables: Vec<TableInfo> = Vec::new();
    for p in props {
        let class = match (p.guess.class, p.public_refusal) {
            (ColumnClass::Public, Some(_)) => ColumnClass::Sensitive,
            (c, _) => c,
        };
        let col = ColumnInfo {
            name: p.column.clone(),
            ty: p.ty,
            class,
            alias: None,
        };
        match tables.iter_mut().find(|t| t.name == p.table) {
            Some(t) => t.columns.push(col),
            None => tables.push(TableInfo {
                name: p.table.clone(),
                alias: None,
                rows: 0,
                columns: vec![col],
            }),
        }
    }
    let mut entities = Vec::new();
    for t in &tables {
        let has = |c: &str| t.columns.iter().any(|x| x.name == c);
        let names: Vec<String> = ["first_name", "last_name", "name"]
            .into_iter()
            .filter(|c| has(c))
            .map(String::from)
            .collect();
        if has("id") && !names.is_empty() {
            entities.push(EntitySpec {
                table: t.name.clone(),
                key: "id".into(),
                names,
                show: vec![],
                word: "record".into(),
                word_da: "post".into(),
            });
        }
    }
    Schema {
        dataset: name.parse().expect("a valid dataset name"),
        tables,
        entities,
        joins: vec![],
    }
}

#[test]
fn fixture_is_synthetic_and_deterministic() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    write_fixture(a.path(), 50, 7).unwrap();
    write_fixture(b.path(), 50, 7).unwrap();
    let ca = std::fs::read_to_string(a.path().join("customers.csv")).unwrap();
    let cb = std::fs::read_to_string(b.path().join("customers.csv")).unwrap();
    assert_eq!(ca, cb);
    assert_eq!(ca.lines().count(), 51);
    for line in ca.lines().skip(1) {
        let refc = line.rsplit(',').next().unwrap();
        assert!(cpr_mod11_ok(refc), "bad check digit");
        assert!(line.contains("@example.invalid"));
        assert!(
            line.contains(",+45 00 "),
            "phone must use the fictional +45 00 prefix"
        );
    }
    let inv = std::fs::read_to_string(a.path().join("invoices.csv")).unwrap();
    assert_eq!(inv.lines().count(), 101);
}
