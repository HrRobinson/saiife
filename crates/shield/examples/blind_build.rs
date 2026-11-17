//! Builds a Data Shield dataset from a directory of CSV files (plan 43 T7):
//! `cargo run --release -p saiife-shield --example blind_build -- <csv dir> <out>`
//! stages the snapshot, accepts every proposal, and finishes with a fixed
//! test key. `<out>` is the dataset directory; its last part is the dataset
//! name (`[a-z][a-z0-9-]{0,31}`). Prints the phases, the row bands and the
//! index size. For the owner smoke (`scripts/blind-smoke.d/10-data.sh`).

#[path = "../tests/fixtures.rs"]
mod fixtures;

use saiife_shield::dataset::{
    finish, propose, stage_snapshot, BuildProgress, DatasetDir, Phase, DEFAULT_K,
};
use saiife_shield::index::IndexKey;
use std::path::PathBuf;
use std::time::Instant;
use zeroize::Zeroizing;

/// A fixed test key: never use it for real data.
fn test_key() -> IndexKey {
    let s = concat!("blind-build-", "example-only-", "fixed-test-key");
    let mut k = [0u8; 32];
    for (d, b) in k.iter_mut().zip(s.bytes().cycle()) {
        *d = b;
    }
    IndexKey(Zeroizing::new(k))
}

fn fail(what: &str, e: impl std::fmt::Display) -> ! {
    eprintln!("blind_build: {what}: {e}");
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [csv, out] = args.as_slice() else {
        eprintln!("usage: blind_build <csv dir> <out dataset dir>");
        std::process::exit(2);
    };
    let (csv, out) = (PathBuf::from(csv), PathBuf::from(out));
    let name = out
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();
    if name.parse::<saiife_shield::schema::DatasetName>().is_err() {
        eprintln!("blind_build: the last part of <out> must be a dataset name");
        std::process::exit(2);
    }
    let dir = DatasetDir { root: out };
    let t0 = Instant::now();
    let mut last: Option<Phase> = None;
    let mut report = |p: BuildProgress| {
        if last != Some(p.phase) {
            println!("phase {:?} at {:.1}s", p.phase, t0.elapsed().as_secs_f64());
            last = Some(p.phase);
        }
    };

    let mut src =
        fixtures::MultiSource::csv_dir(&csv).unwrap_or_else(|e| fail("could not open the CSVs", e));
    let info = stage_snapshot(&dir, &mut src, &mut report)
        .unwrap_or_else(|e| fail("the snapshot failed", e));
    drop(src);
    let props = propose(&info.path, DEFAULT_K).unwrap_or_else(|e| fail("propose failed", e));
    println!(
        "proposals: {} columns at {:.1}s",
        props.len(),
        t0.elapsed().as_secs_f64()
    );
    let schema = fixtures::accept_all(&name, &props);
    let m = finish(
        &dir,
        &schema,
        DEFAULT_K,
        &test_key(),
        &mut |_| Ok(()),
        &mut report,
    )
    .unwrap_or_else(|e| fail("the build failed", e));

    for t in &m.schema.tables {
        println!(
            "table {} rows {} band {}",
            t.name, t.rows, m.rows_bands[&t.name]
        );
    }
    let size = |f: &str| {
        std::fs::metadata(dir.live().join(f))
            .map(|m| m.len())
            .unwrap_or(0)
    };
    println!(
        "index entries {} bytes {} bloom bytes {}",
        m.index.entries,
        size("index.bin"),
        size("index.bloom")
    );
    println!("snapshot bytes {}", size("snapshot.sqlite"));
    println!("built in {:.1}s", t0.elapsed().as_secs_f64());
}
