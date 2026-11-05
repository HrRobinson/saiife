//! `saiife __read-segments <in.json> <out.json>` (debug builds): what the shell
//! readers took each line to be, for scripts/differential-windows.ps1. Files and
//! not pipes, in UTF-8: a Windows pipe would pass the line through a code page.

use saiifeguard::canon::{PathStyle, PathVars};
use saiifeguard::debug_read::{self, RawWord};
use saiifeguard::lexer::Word;
use saiifeguard::winpath;
use saiifeguard::wintable::Dialect;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// The name the script's cmd fixtures call: did the reader see it run?
const STUB: &str = "p19adiffstub";

fn word(w: &Word) -> Value {
    json!({
        "text": w.text,
        "redirect": w.redirect,
        "quoted": w.quoted,
        "substitution": w.has_substitution,
    })
}

fn raw_word(r: &RawWord) -> Value {
    json!({
        "text": r.word.text,
        "redirect": r.word.redirect,
        "quoted": r.word.quoted,
        "from_quote": r.from_quote,
        "block": r.block,
    })
}

fn read_line(dialect: &str, line: &str) -> Result<Value, String> {
    if dialect == "path" {
        let vars = PathVars::new()
            .with_style(PathStyle::Windows)
            .with_cwd(PathBuf::from(r"C:\"));
        return Ok(json!({ "path": winpath::read(line, None, &vars).ok(), "note": null }));
    }
    let dialect = match dialect {
        "powershell" => Dialect::PowerShell,
        "cmd" => Dialect::Cmd,
        other => return Err(format!("unknown dialect {other}")),
    };
    let read = debug_read::read(line, dialect);
    let sees_stub = read
        .segments
        .iter()
        .chain(&read.nested)
        .any(|s| s.iter().any(|w| w.text.eq_ignore_ascii_case(STUB)) && runs_stub(s));
    Ok(json!({
        "commands": read.commands.iter()
            .map(|c| c.iter().map(raw_word).collect::<Vec<_>>())
            .collect::<Vec<_>>(),
        "segments": read.segments.iter()
            .map(|s| s.iter().map(word).collect::<Vec<_>>())
            .collect::<Vec<_>>(),
        "sees_stub": sees_stub,
        "note": read.note,
    }))
}

/// The stub in command position, past assignments and redirections.
fn runs_stub(seg: &[Word]) -> bool {
    let mut words = seg.iter();
    while let Some(w) = words.next() {
        if w.redirect {
            words.next();
        } else if !w.assignment {
            return w.text.eq_ignore_ascii_case(STUB);
        }
    }
    false
}

fn convert(input: &Path, output: &Path) -> Result<(), String> {
    let text = std::fs::read_to_string(input).map_err(|e| format!("{}: {e}", input.display()))?;
    let requests: Vec<Value> = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(requests.len());
    for r in &requests {
        let field = |name: &str| r.get(name).and_then(Value::as_str).unwrap_or("");
        out.push(read_line(field("dialect"), field("line"))?);
    }
    let text = serde_json::to_string(&out).map_err(|e| e.to_string())?;
    std::fs::write(output, text).map_err(|e| format!("{}: {e}", output.display()))
}

pub fn run(input: &Path, output: &Path) -> ExitCode {
    match convert(input, output) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("saiife: {e}");
            ExitCode::from(2)
        }
    }
}
