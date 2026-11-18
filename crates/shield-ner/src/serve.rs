//! The helper side of `saiife-ner/1` (R46-4): the serve loop, the phrase
//! fake, and what both helper binaries share (arguments, bounded file reads,
//! the silent panic hook, the sandbox).
//!
//! **Never echoes input.** Every error text is a fixed `&'static str` (at
//! most [`MAX_ERROR`] chars); a request's text never reaches stdout, stderr
//! or a panic message that is printed (the binaries install
//! [`install_silent_panic_hook`] first thing).
//!
//! **Bounded reads.** A request line is read with at most [`MAX_LINE`]
//! bytes in memory; a longer line is answered `Error{id: 0}` and skipped up
//! to its newline, and the loop goes on with the next line.

use crate::labels::LABELS_MAX_BYTES;
use crate::model::{NerModel, MODEL_MAX_BYTES};
use crate::wordpiece::VOCAB_MAX_BYTES;
use crate::NerError;
use saiife_shield::ner_proto::{
    decode, encode, Answer, Request, WireSpan, MAX_ERROR, MAX_LINE, MAX_TEXT, PROTO,
};
use std::ffi::OsString;
use std::io::{self, BufRead, Read, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

/// A name detector the serve loop answers with.
pub trait Detect {
    /// Spans with byte offsets into `text`. Errors carry fixed texts.
    fn detect(&self, text: &str) -> Result<Vec<WireSpan>, NerError>;
    /// The entity types it reports, for the hello.
    fn labels(&self) -> Vec<String>;
}

impl Detect for NerModel {
    fn detect(&self, text: &str) -> Result<Vec<WireSpan>, NerError> {
        NerModel::detect(self, text)
    }
    fn labels(&self) -> Vec<String> {
        NerModel::labels(self)
    }
}

/// The fixed error texts of the protocol.
pub const ERR_MALFORMED: &str = "malformed request";
pub const ERR_LINE_TOO_LONG: &str = "request line too long";
pub const ERR_TEXT_TOO_LONG: &str = "text too long";
pub const ERR_FAILED: &str = "detection failed";
/// The hello replacement when the model, vocab or labels do not load.
pub const ERR_LOAD: &str = "cannot load the model";

/// The four wire labels, in hello order.
const WIRE_LABELS: [&str; 4] = ["PER", "ORG", "LOC", "MISC"];

/// An error answer; the text is cut to [`MAX_ERROR`] chars.
pub fn error_answer(id: u64, text: &'static str) -> Answer {
    Answer::Error {
        id,
        error: text.chars().take(MAX_ERROR).collect(),
    }
}

/// What a detector error says on the wire: fixed texts only.
fn wire_error(e: &NerError) -> &'static str {
    match e {
        NerError::Model(s) => s,
        NerError::Labels(_) => "bad labels file",
        NerError::Vocab => "bad vocab file",
        NerError::Hash(_) => "hash mismatch",
    }
}

enum Got {
    Eof,
    Line,
    TooLong,
}

/// Reads one line (its `\n` kept) into `buf`, holding at most `max` bytes.
/// A longer line is consumed up to its newline and reported `TooLong`. A
/// last line without a newline still counts.
fn read_line(input: &mut dyn BufRead, buf: &mut Vec<u8>, max: usize) -> io::Result<Got> {
    buf.clear();
    let mut over = false;
    let mut any = false;
    loop {
        let avail = match input.fill_buf() {
            Ok(a) => a,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if avail.is_empty() {
            return Ok(match (over, any) {
                (true, _) => Got::TooLong,
                (false, true) => Got::Line,
                (false, false) => Got::Eof,
            });
        }
        any = true;
        let (n, done) = match avail.iter().position(|b| *b == b'\n') {
            Some(i) => (i + 1, true),
            None => (avail.len(), false),
        };
        if !over {
            if buf.len().saturating_add(n) > max {
                over = true;
                buf.clear();
            } else {
                buf.extend_from_slice(&avail[..n]);
            }
        }
        input.consume(n);
        if done {
            return Ok(if over { Got::TooLong } else { Got::Line });
        }
    }
}

/// One request line to one answer. A detector panic answers
/// [`ERR_FAILED`] (the panic hook must be silent: see the module doc).
fn handle(d: &dyn Detect, line: &[u8]) -> Answer {
    let Ok(Request::Detect { id, text }) = decode::<Request>(line) else {
        return error_answer(0, ERR_MALFORMED);
    };
    if text.len() > MAX_TEXT {
        return error_answer(id, ERR_TEXT_TOO_LONG);
    }
    match catch_unwind(AssertUnwindSafe(|| d.detect(&text))) {
        Ok(Ok(mut spans)) => {
            // Only spans the client can use: in bounds, on char boundaries.
            spans.retain(|s| s.to_span(&text).is_some());
            Answer::Spans { id, spans }
        }
        Ok(Err(e)) => error_answer(id, wire_error(&e)),
        Err(_) => error_answer(id, ERR_FAILED),
    }
}

/// The hello, then one answer per request line until EOF. A bad line is
/// answered `Error{id: 0}` and the loop goes on; a text over [`MAX_TEXT`]
/// bytes is answered with an error for its id. Returns on EOF or a write
/// error.
pub fn serve(d: &dyn Detect, input: &mut dyn BufRead, output: &mut dyn Write) -> io::Result<()> {
    let hello = Answer::Hello {
        proto: PROTO,
        version: env!("CARGO_PKG_VERSION").to_string(),
        labels: d.labels(),
    };
    output.write_all(&encode(&hello))?;
    output.flush()?;
    let mut buf = Vec::with_capacity(4096);
    loop {
        let answer = match read_line(input, &mut buf, MAX_LINE)? {
            Got::Eof => return Ok(()),
            Got::TooLong => error_answer(0, ERR_LINE_TOO_LONG),
            Got::Line => handle(d, &buf),
        };
        buf.clear();
        output.write_all(&encode(&answer))?;
        output.flush()?;
    }
}

/// The test fake: exact, case-insensitive (char by char) matches of whole
/// phrases between word boundaries; score 1.0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhraseDetector {
    /// `(label, phrase)`; the label is `PER`, `ORG`, `LOC` or `MISC`.
    pub phrases: Vec<(String, String)>,
}

/// Largest phrases file.
pub const PHRASES_MAX_BYTES: usize = 1024 * 1024;

fn bad_phrases() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "bad phrases file")
}

impl PhraseDetector {
    /// Lines `PER<TAB>Søren Ærø`; empty lines and `#` lines are skipped.
    pub fn from_file(p: &Path) -> io::Result<PhraseDetector> {
        let bytes = read_capped(p, PHRASES_MAX_BYTES)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| bad_phrases())?;
        let mut phrases = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            let (label, phrase) = line.split_once('\t').ok_or_else(bad_phrases)?;
            let phrase = phrase.trim();
            if !WIRE_LABELS.contains(&label) || phrase.is_empty() {
                return Err(bad_phrases());
            }
            phrases.push((label.to_string(), phrase.to_string()));
        }
        Ok(PhraseDetector { phrases })
    }
}

fn same_ci(a: char, b: char) -> bool {
    a == b || a.to_lowercase().eq(b.to_lowercase())
}

/// The end byte of `phrase` matched at the start of `rest`, if it is.
fn match_len(rest: &str, phrase: &str) -> Option<usize> {
    let mut it = rest.char_indices();
    let mut end = 0;
    for pc in phrase.chars() {
        let (i, tc) = it.next()?;
        if !same_ci(tc, pc) {
            return None;
        }
        end = i + tc.len_utf8();
    }
    Some(end)
}

impl Detect for PhraseDetector {
    fn detect(&self, text: &str) -> Result<Vec<WireSpan>, NerError> {
        if text.len() > MAX_TEXT {
            return Err(NerError::Model(ERR_TEXT_TOO_LONG));
        }
        let mut order: Vec<&(String, String)> = self.phrases.iter().collect();
        order.sort_by_key(|(_, p)| std::cmp::Reverse(p.len()));
        let mut out = Vec::new();
        let mut prev: Option<char> = None;
        let mut skip_to = 0;
        for (i, c) in text.char_indices() {
            let word_start = !prev.is_some_and(char::is_alphanumeric);
            prev = Some(c);
            if i < skip_to || !word_start {
                continue;
            }
            let Some(rest) = text.get(i..) else { continue };
            for (label, phrase) in &order {
                let Some(n) = match_len(rest, phrase) else {
                    continue;
                };
                let word_end = !rest
                    .get(n..)
                    .and_then(|r| r.chars().next())
                    .is_some_and(char::is_alphanumeric);
                if n > 0 && word_end {
                    out.push(WireSpan {
                        start: i,
                        end: i + n,
                        label: label.clone(),
                        score: 1.0,
                    });
                    skip_to = i + n;
                    break;
                }
            }
        }
        Ok(out)
    }

    fn labels(&self) -> Vec<String> {
        WIRE_LABELS
            .into_iter()
            .filter(|l| self.phrases.iter().any(|(x, _)| x == l))
            .map(String::from)
            .collect()
    }
}

/// Reads `p` whole, refusing more than `max` bytes (never more than
/// `max + 1` bytes are read).
pub fn read_capped(p: &Path, max: usize) -> io::Result<Vec<u8>> {
    let f = std::fs::File::open(p)?;
    let mut out = Vec::new();
    f.take(max as u64 + 1).read_to_end(&mut out)?;
    if out.len() > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file too large"));
    }
    Ok(out)
}

/// A lowercase hex SHA-256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in Sha256::digest(bytes) {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Replaces the panic hook with one that prints nothing: the default hook
/// prints the panic message, which can carry request text or WordPiece
/// ids (R46-4). Both helpers install it before anything else.
pub fn install_silent_panic_hook() {
    std::panic::set_hook(Box::new(|_| {}));
}

/// The usage line (fixed).
pub const NER_USAGE: &str = "usage: saiife-ner --model <path> --vocab <path> --labels <path> --sha256-model <hex> --sha256-vocab <hex> --sha256-labels <hex>";

/// `saiife-ner`'s arguments (R46-4 fixed values).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NerArgs {
    pub model: PathBuf,
    pub vocab: PathBuf,
    pub labels: PathBuf,
    /// Lowercase hex SHA-256 of each file.
    pub sha256_model: String,
    pub sha256_vocab: String,
    pub sha256_labels: String,
}

fn hex64(v: OsString) -> Option<String> {
    let s = v.into_string().ok()?.to_ascii_lowercase();
    (s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())).then_some(s)
}

impl NerArgs {
    /// Each of the six flags exactly once, each with a value; hashes are 64
    /// hex digits. Anything else is refused (the caller prints
    /// [`NER_USAGE`]).
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<NerArgs, &'static str> {
        let mut paths: [Option<PathBuf>; 3] = [None, None, None];
        let mut sums: [Option<String>; 3] = [None, None, None];
        let mut it = args.into_iter();
        while let Some(flag) = it.next() {
            let value = it.next().ok_or("a flag without a value")?;
            let (is_path, i) = match flag.to_str() {
                Some("--model") => (true, 0),
                Some("--vocab") => (true, 1),
                Some("--labels") => (true, 2),
                Some("--sha256-model") => (false, 0),
                Some("--sha256-vocab") => (false, 1),
                Some("--sha256-labels") => (false, 2),
                _ => return Err("unknown argument"),
            };
            if is_path {
                if value.is_empty() || paths[i].replace(PathBuf::from(value)).is_some() {
                    return Err("bad or repeated path");
                }
            } else {
                let h = hex64(value).ok_or("bad sha256")?;
                if sums[i].replace(h).is_some() {
                    return Err("repeated sha256");
                }
            }
        }
        let [Some(model), Some(vocab), Some(labels)] = paths else {
            return Err("missing path");
        };
        let [Some(sha256_model), Some(sha256_vocab), Some(sha256_labels)] = sums else {
            return Err("missing sha256");
        };
        Ok(NerArgs {
            model,
            vocab,
            labels,
            sha256_model,
            sha256_vocab,
            sha256_labels,
        })
    }
}

/// How `saiife-ner` ends before serving, after the sandbox is up.
#[derive(Debug, PartialEq, Eq)]
pub enum LoadFailure {
    /// A file's SHA-256 does not match its argument (`model`, `vocab` or
    /// `labels`): exit 3, nothing parsed.
    Hash(&'static str),
    /// A file could not be read or is over its cap, or the model does not
    /// load: exit 4 after the [`ERR_LOAD`] line.
    Load,
}

/// Reads the three files (each capped), checks each against its hash
/// before anything is parsed, then loads the model. Run it confined.
pub fn load_checked(a: &NerArgs) -> Result<NerModel, LoadFailure> {
    let files = [
        (&a.model, MODEL_MAX_BYTES, &a.sha256_model, "model"),
        (&a.vocab, VOCAB_MAX_BYTES, &a.sha256_vocab, "vocab"),
        (&a.labels, LABELS_MAX_BYTES, &a.sha256_labels, "labels"),
    ];
    let mut bytes = Vec::with_capacity(3);
    for (p, cap, _, _) in &files {
        bytes.push(read_capped(p, *cap).map_err(|_| LoadFailure::Load)?);
    }
    for ((_, _, want, name), b) in files.iter().zip(&bytes) {
        if sha256_hex(b) != **want {
            return Err(LoadFailure::Hash(name));
        }
    }
    // Moved in, so the file bytes are freed as soon as the model is built.
    let [model, vocab, labels]: [Vec<u8>; 3] = bytes.try_into().map_err(|_| LoadFailure::Load)?;
    catch_unwind(AssertUnwindSafe(move || {
        NerModel::load(&model, &vocab, &labels)
    }))
    .ok()
    .and_then(Result::ok)
    .ok_or(LoadFailure::Load)
}

/// Open files a helper may hold (R46-6): stdin, stdout, stderr, the
/// Landlock ruleset and the path descriptors of its rules while it is
/// built, one file being read, and slack.
pub const HELPER_NOFILE: u64 = 32;

/// R46-6: resource limits, then the sandbox ([`Profile::Ner`]: read only
/// `read_files`, no network, the Ner seccomp allowlist, no new process).
/// Call it single-threaded, before any model byte is read.
///
/// [`Profile::Ner`]: saiife_system::sandbox::Profile::Ner
#[cfg(target_os = "linux")]
pub fn confine(
    read_files: &[&Path],
) -> Result<saiife_system::sandbox::Confinement, saiife_system::sandbox::SandboxError> {
    use saiife_system::sandbox::{apply_rlimits, confine_helper, Profile, Rlimits};
    apply_rlimits(&Rlimits {
        // A long-lived helper: no CPU limit.
        cpu_secs: 0,
        as_bytes: crate::model::HELPER_AS_BYTES,
        nofile: HELPER_NOFILE,
    })?;
    confine_helper(Profile::Ner, read_files, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn error_texts_are_capped() {
        let long: &'static str = Box::leak("é".repeat(MAX_ERROR + 50).into_boxed_str());
        match error_answer(1, long) {
            Answer::Error { error, .. } => assert_eq!(error.chars().count(), MAX_ERROR),
            _ => unreachable!(),
        }
        for t in [
            ERR_MALFORMED,
            ERR_LINE_TOO_LONG,
            ERR_TEXT_TOO_LONG,
            ERR_FAILED,
            ERR_LOAD,
        ] {
            assert!(t.chars().count() <= MAX_ERROR);
        }
    }

    #[test]
    fn args_rules() {
        let h = "a".repeat(64);
        let full = [
            "--model",
            "m",
            "--vocab",
            "v",
            "--labels",
            "l",
            "--sha256-model",
            &h,
            "--sha256-vocab",
            &h,
            "--sha256-labels",
            &h,
        ];
        let a = NerArgs::parse(os(&full)).unwrap();
        assert_eq!(a.model, PathBuf::from("m"));
        assert_eq!(a.sha256_labels, h);
        let upper = "A".repeat(64);
        let mut v = full.to_vec();
        v[7] = &upper;
        assert_eq!(NerArgs::parse(os(&v)).unwrap().sha256_model, h);
        assert!(NerArgs::parse(os(&full[..11])).is_err());
        assert!(NerArgs::parse(os(&full[..10])).is_err());
        let mut v = full.to_vec();
        v.extend(["--model", "x"]);
        assert!(NerArgs::parse(os(&v)).is_err());
        let mut v = full.to_vec();
        v[9] = "abc";
        assert!(NerArgs::parse(os(&v)).is_err());
        let mut v = full.to_vec();
        v[0] = "--bogus";
        assert!(NerArgs::parse(os(&v)).is_err());
        let mut v = full.to_vec();
        v[1] = "";
        assert!(NerArgs::parse(os(&v)).is_err());
    }

    #[test]
    fn phrase_matching_is_safe_on_any_utf8() {
        let d = PhraseDetector {
            phrases: vec![("PER".into(), "Åse".into()), ("ORG".into(), "İ".into())],
        };
        for t in [
            "",
            "å",
            "ÅSE",
            "xÅse",
            "Åsex",
            "🙂Åse🙂",
            "\u{0130}",
            "a\u{0301}se",
        ] {
            for s in d.detect(t).unwrap() {
                assert!(s.to_span(t).is_some(), "{t:?}");
            }
        }
        assert_eq!(d.detect("hej ÅSE!").unwrap().len(), 1);
        assert_eq!(d.labels(), vec!["PER", "ORG"]);
    }
}
