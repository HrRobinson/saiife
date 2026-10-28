//! Writes `$OUT_DIR/builtin.rs`: the built-in connector list, one entry per
//! `connectors/*.toml` (sorted, `test-echo.toml` left out), so a connector
//! task adds a file and nothing else.

use std::fmt::Write as _;
use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let dir = root.join("connectors");
    println!("cargo:rerun-if-changed={}", dir.display());
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| {
            e.expect("connectors entry")
                .file_name()
                .into_string()
                .expect("connector file names are UTF-8")
        })
        .filter(|n| n.ends_with(".toml") && n != "test-echo.toml")
        .collect();
    names.sort();
    let mut out = String::from("const BUILTIN: &[(&str, &str)] = &[\n");
    for n in &names {
        let path = dir.join(n);
        println!("cargo:rerun-if-changed={}", path.display());
        let path = path.to_str().expect("the connector path is UTF-8");
        writeln!(out, "    ({n:?}, include_str!({path:?})),").unwrap();
    }
    out.push_str("];\n");
    let dest = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("builtin.rs");
    std::fs::write(&dest, out).unwrap_or_else(|e| panic!("{}: {e}", dest.display()));
}
