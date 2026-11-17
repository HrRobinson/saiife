//! Writes the synthetic Data Shield fixture (plan 43 T3):
//! `cargo run -p saiife-shield --example blind_fixture -- --rows N [--invoices M] --seed S --out DIR`
//! gives `DIR/customers.csv` (N rows) and `DIR/invoices.csv` (M rows, default 2N).

#[path = "../tests/fixtures.rs"]
mod fixtures;

use std::path::PathBuf;

fn main() {
    let (mut rows, mut seed, mut out) = (1000u64, 1u64, None::<PathBuf>);
    let mut invoices = None::<u64>;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let v = args.next();
        match (a.as_str(), v) {
            ("--rows", Some(v)) => rows = v.parse().unwrap_or_else(|_| usage()),
            ("--invoices", Some(v)) => invoices = Some(v.parse().unwrap_or_else(|_| usage())),
            ("--seed", Some(v)) => seed = v.parse().unwrap_or_else(|_| usage()),
            ("--out", Some(v)) => out = Some(PathBuf::from(v)),
            _ => usage(),
        }
    }
    let out = out.unwrap_or_else(|| usage());
    if let Err(e) = std::fs::create_dir_all(&out).and_then(|()| {
        fixtures::write_fixture_sized(&out, rows, invoices.unwrap_or(rows.saturating_mul(2)), seed)
    }) {
        eprintln!("blind_fixture: could not write the fixture: {e}");
        std::process::exit(1);
    }
    println!(
        "wrote {} and {}",
        out.join("customers.csv").display(),
        out.join("invoices.csv").display()
    );
}

fn usage() -> ! {
    eprintln!("usage: blind_fixture --rows N [--invoices M] --seed S --out DIR");
    std::process::exit(2);
}
