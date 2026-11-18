//! The `saiife-ner/1` serve loop in process, and the two helper binaries as
//! real processes under their sandbox (Landlock, seccomp, rlimits).

mod common;

use saiife_shield::ner_proto::{decode, encode, Answer, Request, WireSpan, MAX_LINE, MAX_TEXT};
use saiife_shield_ner::serve::{serve, Detect, PhraseDetector};
use saiife_shield_ner::NerError;

/// A rare synthetic name: no output of a failing request may hold it.
const RARE: &str = "Ærøskøbing-Ølgaard";

fn danish() -> PhraseDetector {
    PhraseDetector {
        phrases: vec![
            ("PER".to_string(), "Søren Ærø".to_string()),
            ("LOC".to_string(), "Aarhus".to_string()),
        ],
    }
}

fn detect_line(id: u64, text: &str) -> Vec<u8> {
    encode(&Request::Detect {
        id,
        text: text.to_string(),
    })
}

/// Runs `serve` on `input`; every output line decoded.
fn run(d: &dyn Detect, input: &[u8]) -> Vec<Answer> {
    let mut out = Vec::new();
    serve(d, &mut &input[..], &mut out).unwrap();
    answers(&out)
}

fn answers(out: &[u8]) -> Vec<Answer> {
    out.split_inclusive(|b| *b == b'\n')
        .map(|l| decode::<Answer>(l).expect("every output line is an answer"))
        .collect()
}

fn hello_labels(a: &Answer) -> Vec<String> {
    match a {
        Answer::Hello {
            proto,
            version,
            labels,
        } => {
            assert_eq!(*proto, 1);
            assert_eq!(version, env!("CARGO_PKG_VERSION"));
            labels.clone()
        }
        other => panic!("expected hello, got {other:?}"),
    }
}

fn spans_of(a: &Answer, want_id: u64) -> Vec<WireSpan> {
    match a {
        Answer::Spans { id, spans } if *id == want_id => spans.clone(),
        other => panic!("expected spans for {want_id}, got {other:?}"),
    }
}

fn error_of(a: &Answer, want_id: u64) -> String {
    match a {
        Answer::Error { id, error } if *id == want_id => {
            assert!(error.chars().count() <= 256);
            error.clone()
        }
        other => panic!("expected an error for {want_id}, got {other:?}"),
    }
}

#[test]
fn serve_hello_then_spans() {
    let t1 = "Hvad skylder søren ærø?";
    let t2 = "Bor SØREN ÆRØ i Aarhus?";
    let mut input = detect_line(1, t1);
    input.extend(detect_line(2, t2));
    input.extend(detect_line(3, "ingen navne her"));
    let a = run(&danish(), &input);
    assert_eq!(a.len(), 4);
    assert_eq!(hello_labels(&a[0]), vec!["PER", "LOC"]);
    let s1 = spans_of(&a[1], 1);
    assert_eq!(s1.len(), 1);
    assert_eq!((s1[0].start, s1[0].end), (13, 25));
    assert_eq!(&t1[s1[0].start..s1[0].end], "søren ærø");
    assert_eq!(s1[0].label, "PER");
    let s2 = spans_of(&a[2], 2);
    let got: Vec<(&str, &str)> = s2
        .iter()
        .map(|s| (s.label.as_str(), &t2[s.start..s.end]))
        .collect();
    assert_eq!(got, vec![("PER", "SØREN ÆRØ"), ("LOC", "Aarhus")]);
    assert!(spans_of(&a[3], 3).is_empty());
    // A phrase inside a longer word is not a match.
    let a = run(&danish(), &detect_line(4, "Aarhusianer"));
    assert!(spans_of(&a[1], 4).is_empty());
    // No request: hello only.
    assert_eq!(run(&danish(), b"").len(), 1);
}

#[test]
fn serve_bad_line_continues() {
    let mut input = b"not json at all\n".to_vec();
    input.extend(br#"{"op":"detect","id":5,"text":"a","extra":1}"#);
    input.push(b'\n');
    input.extend(b"\xff\xfe\n");
    input.extend(b"\n");
    input.extend(detect_line(6, "Søren Ærø"));
    // The last line has no newline: still answered.
    input.extend(br#"{"op":"detect","id":7,"text":"Aarhus"}"#);
    let a = run(&danish(), &input);
    assert_eq!(a.len(), 7);
    for b in &a[1..5] {
        error_of(b, 0);
    }
    assert_eq!(spans_of(&a[5], 6).len(), 1);
    assert_eq!(spans_of(&a[6], 7).len(), 1);
}

#[test]
fn oversize_text_errors() {
    // Exactly MAX_TEXT bytes is fine; one more is an error with the id.
    let ok = "a".repeat(MAX_TEXT);
    let big = "a".repeat(MAX_TEXT + 1);
    let mut input = detect_line(1, &ok);
    input.extend(detect_line(2, &big));
    // A line over MAX_LINE: error id 0, then the next line is read again.
    let mut long = br#"{"op":"detect","id":3,"text":""#.to_vec();
    long.resize(MAX_LINE * 3, b'a');
    long.extend(b"\"}\n");
    input.extend(&long);
    input.extend(detect_line(4, "Søren Ærø"));
    // A line of exactly MAX_LINE bytes (newline included) is read.
    let mut exact = br#"{"op":"detect","id":5,"text":"x"}"#.to_vec();
    exact.resize(MAX_LINE - 1, b' ');
    exact.push(b'\n');
    input.extend(&exact);
    let a = run(&danish(), &input);
    assert_eq!(a.len(), 6);
    assert!(spans_of(&a[1], 1).is_empty());
    assert_eq!(error_of(&a[2], 2), "text too long");
    error_of(&a[3], 0);
    assert_eq!(spans_of(&a[4], 4).len(), 1);
    assert!(spans_of(&a[5], 5).is_empty());
}

/// A detector that fails or panics with the request text in its message.
struct Hostile {
    panic: bool,
}

impl Detect for Hostile {
    fn detect(&self, text: &str) -> Result<Vec<WireSpan>, NerError> {
        if self.panic {
            panic!("{text}");
        }
        Err(NerError::Model("inference failed"))
    }
    fn labels(&self) -> Vec<String> {
        vec!["PER".to_string()]
    }
}

#[test]
fn detector_failures_answer_fixed_errors() {
    for panic in [false, true] {
        let mut out = Vec::new();
        let input = detect_line(9, RARE);
        serve(&Hostile { panic }, &mut &input[..], &mut out).unwrap();
        let text = String::from_utf8(out.clone()).unwrap();
        assert!(!text.contains(RARE), "{text}");
        let a = answers(&out);
        assert_eq!(a.len(), 2);
        error_of(&a[1], 9);
    }
}

#[test]
fn phrases_file_rules() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("phrases.tsv");
    std::fs::write(&p, "# comment\n\nPER\tSøren Ærø\nLOC\tAarhus\n").unwrap();
    let d = PhraseDetector::from_file(&p).unwrap();
    assert_eq!(d.phrases, danish().phrases);
    for bad in ["PER Søren\n", "per\tSøren\n", "XYZ\tSøren\n", "PER\t\n"] {
        std::fs::write(&p, bad).unwrap();
        assert!(PhraseDetector::from_file(&p).is_err(), "{bad:?}");
    }
}

#[cfg(target_os = "linux")]
mod process {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    pub struct Ran {
        pub code: Option<i32>,
        pub stdout: Vec<u8>,
        pub stderr: Vec<u8>,
    }

    /// Runs `exe args`, an empty environment, `input` on stdin then EOF;
    /// killed after 120 s.
    pub fn run_helper(exe: &str, args: &[&std::ffi::OsStr], input: &[u8]) -> Ran {
        let mut child = Command::new(exe)
            .args(args)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = child.stdout.take().unwrap();
        let mut err = child.stderr.take().unwrap();
        let t_out = std::thread::spawn(move || {
            let mut v = Vec::new();
            let _ = out.read_to_end(&mut v);
            v
        });
        let t_err = std::thread::spawn(move || {
            let mut v = Vec::new();
            let _ = err.read_to_end(&mut v);
            v
        });
        {
            let mut stdin = child.stdin.take().unwrap();
            // The helper may exit before reading (a refusal): ignore EPIPE.
            let _ = stdin.write_all(input);
        }
        let start = Instant::now();
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break s;
            }
            if start.elapsed() > Duration::from_secs(120) {
                let _ = child.kill();
                panic!("helper did not exit");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        Ran {
            code: status.code(),
            stdout: t_out.join().unwrap(),
            stderr: t_err.join().unwrap(),
        }
    }

    pub fn landlock_or_skip(test: &str) -> bool {
        if saiife_system::sandbox::landlock_abi() == 0 {
            eprintln!("SKIPPED {test}: this kernel has no Landlock, the helper cannot be confined");
            return false;
        }
        let userns = std::fs::read_to_string("/proc/sys/user/max_user_namespaces")
            .map(|s| s.trim() != "0")
            .unwrap_or(true)
            && std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
                .map(|s| s.trim() != "0")
                .unwrap_or(true);
        if !userns {
            eprintln!(
                "NOTE {test}: no unprivileged user namespaces here: the helper runs without its empty network namespace (Landlock and seccomp still apply)"
            );
        }
        true
    }

    pub fn hex(b: &[u8]) -> String {
        Sha256::digest(b)
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect()
    }

    pub struct Files {
        pub _dir: tempfile::TempDir,
        pub model: PathBuf,
        pub vocab: PathBuf,
        pub labels: PathBuf,
        pub sums: [String; 3],
    }

    pub fn write_files(model: &[u8], vocab: &[u8], labels: &[u8]) -> Files {
        let dir = tempfile::tempdir().unwrap();
        let w = |name: &str, b: &[u8]| {
            let p = dir.path().join(name);
            std::fs::write(&p, b).unwrap();
            p
        };
        Files {
            model: w("model.onnx", model),
            vocab: w("vocab.txt", vocab),
            labels: w("labels.json", labels),
            sums: [hex(model), hex(vocab), hex(labels)],
            _dir: dir,
        }
    }

    pub fn ner_args<'a>(f: &'a Files, sums: &'a [String; 3]) -> Vec<&'a std::ffi::OsStr> {
        let o = |s: &'a str| std::ffi::OsStr::new(s);
        let p = |p: &'a Path| p.as_os_str();
        vec![
            o("--model"),
            p(&f.model),
            o("--vocab"),
            p(&f.vocab),
            o("--labels"),
            p(&f.labels),
            o("--sha256-model"),
            o(&sums[0]),
            o("--sha256-vocab"),
            o(&sums[1]),
            o("--sha256-labels"),
            o(&sums[2]),
        ]
    }

    const NER: &str = env!("CARGO_BIN_EXE_saiife-ner");

    #[test]
    fn helper_refuses_bad_hash() {
        if !landlock_or_skip("helper_refuses_bad_hash") {
            return;
        }
        // Not parseable as any of the three: a parse would print an error
        // line on stdout.
        let f = write_files(b"garbage model", b"garbage vocab", b"garbage labels");
        for (i, name) in ["model", "vocab", "labels"].iter().enumerate() {
            let mut sums = f.sums.clone();
            sums[i] = "0".repeat(64);
            let r = run_helper(NER, &ner_args(&f, &sums), b"");
            assert_eq!(r.code, Some(3), "{name}");
            assert!(r.stdout.is_empty(), "{name}: no hello, nothing parsed");
            assert_eq!(
                String::from_utf8_lossy(&r.stderr),
                format!("hash mismatch for {name}\n")
            );
        }
        // Bad arguments: usage, exit 2, nothing read.
        let r = run_helper(NER, &[std::ffi::OsStr::new("--model")], b"");
        assert_eq!(r.code, Some(2));
        assert!(r.stdout.is_empty());
    }

    #[test]
    fn real_helper_answers_under_the_sandbox() {
        if !landlock_or_skip("real_helper_answers_under_the_sandbox") {
            return;
        }
        let inputs = ["input_ids", "attention_mask"];
        let f = write_files(
            &common::model_bytes(&inputs),
            &common::vocab(),
            &common::labels_json(5, &inputs),
        );
        let text = "Hvad skylder Søren i Aarhus?";
        let mut input = detect_line(1, text);
        input.extend(detect_line(2, &format!("{text} {text}")));
        input.extend(detect_line(3, &"a".repeat(MAX_TEXT + 1)));
        let r = run_helper(NER, &ner_args(&f, &f.sums), &input);
        assert_eq!(
            r.code,
            Some(0),
            "stderr: {}",
            String::from_utf8_lossy(&r.stderr)
        );
        assert!(
            r.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&r.stderr)
        );
        let a = answers(&r.stdout);
        assert_eq!(a.len(), 4);
        assert_eq!(hello_labels(&a[0]), vec!["PER", "LOC"]);
        let got: Vec<(String, &str)> = spans_of(&a[1], 1)
            .iter()
            .map(|s| (s.label.clone(), &text[s.start..s.end]))
            .collect();
        assert_eq!(
            got,
            vec![("PER".to_string(), "Søren"), ("LOC".to_string(), "Aarhus")]
        );
        assert_eq!(spans_of(&a[2], 2).len(), 4);
        assert_eq!(error_of(&a[3], 3), "text too long");
    }

    /// The live helper, between two requests: seccomp in filter mode with
    /// the Ner filters, no_new_privs, the R46-6 limits, and one thread after
    /// a model run (tract started none; it could not: RLIMIT_NPROC 0).
    #[test]
    fn real_helper_is_confined_while_serving() {
        use std::io::BufRead;
        if !landlock_or_skip("real_helper_is_confined_while_serving") {
            return;
        }
        let inputs = ["input_ids", "attention_mask"];
        let f = write_files(
            &common::model_bytes(&inputs),
            &common::vocab(),
            &common::labels_json(5, &inputs),
        );
        let mut child = Command::new(NER)
            .args(ner_args(&f, &f.sums))
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let mut stdin = child.stdin.take().unwrap();
        let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        hello_labels(&decode::<Answer>(line.as_bytes()).unwrap());
        stdin
            .write_all(&detect_line(1, "Hvad skylder Søren i Aarhus?"))
            .unwrap();
        line.clear();
        stdout.read_line(&mut line).unwrap();
        assert_eq!(
            spans_of(&decode::<Answer>(line.as_bytes()).unwrap(), 1).len(),
            2
        );
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).unwrap();
        let tasks = std::fs::read_dir(format!("/proc/{pid}/task"))
            .unwrap()
            .count();
        drop(stdin);
        let code = child.wait().unwrap().code();
        let field = |name: &str| {
            status
                .lines()
                .find_map(|l| l.strip_prefix(name))
                .map(str::trim)
                .unwrap_or_default()
                .to_string()
        };
        assert_eq!(field("Seccomp:"), "2", "{status}");
        // The Ner profile: the clone3 -> ENOSYS filter, then the allowlist.
        assert_eq!(field("Seccomp_filters:"), "2", "{status}");
        assert_eq!(field("NoNewPrivs:"), "1");
        assert_eq!(field("Threads:"), "1");
        assert_eq!(tasks, 1);
        let limit = |name: &str| {
            limits
                .lines()
                .find(|l| l.starts_with(name))
                .map(|l| {
                    l[name.len()..]
                        .split_whitespace()
                        .take(2)
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default()
        };
        assert_eq!(limit("Max processes"), "0 0");
        assert_eq!(limit("Max address space"), "4294967296 4294967296");
        assert_eq!(limit("Max open files"), "32 32");
        assert_eq!(limit("Max file size"), "0 0");
        assert_eq!(limit("Max core file size"), "0 0");
        assert_eq!(limit("Max cpu time"), "unlimited unlimited");
        assert_eq!(code, Some(0));
    }

    #[test]
    fn real_helper_broken_model_errors() {
        if !landlock_or_skip("real_helper_broken_model_errors") {
            return;
        }
        let inputs = ["input_ids", "attention_mask"];
        let model = common::model_bytes(&inputs);
        let f = write_files(
            &model[..model.len() / 2],
            &common::vocab(),
            &common::labels_json(5, &inputs),
        );
        let r = run_helper(NER, &ner_args(&f, &f.sums), &detect_line(1, RARE));
        assert_eq!(r.code, Some(4));
        assert_eq!(
            String::from_utf8_lossy(&r.stdout),
            "{\"t\":\"error\",\"id\":0,\"error\":\"cannot load the model\"}\n"
        );
        assert!(r.stderr.is_empty());
    }

    #[cfg(feature = "fake")]
    mod fake {
        use super::*;

        const FAKE: &str = env!("CARGO_BIN_EXE_saiife-fake-ner");

        fn phrases() -> (tempfile::TempDir, PathBuf) {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("phrases.tsv");
            std::fs::write(&p, "PER\tSøren Ærø\nLOC\tAarhus\n").unwrap();
            (dir, p)
        }

        fn args<'a>(p: &'a Path, extra: &[&'a str]) -> Vec<&'a std::ffi::OsStr> {
            let mut v = vec![std::ffi::OsStr::new("--phrases"), p.as_os_str()];
            v.extend(extra.iter().map(|s| std::ffi::OsStr::new(*s)));
            v
        }

        #[test]
        fn fake_helper_end_to_end() {
            if !landlock_or_skip("fake_helper_end_to_end") {
                return;
            }
            let (_d, p) = phrases();
            let text = "Hvad skylder Søren Ærø i Aarhus? 🙂";
            let r = run_helper(FAKE, &args(&p, &[]), &detect_line(42, text));
            assert_eq!(r.code, Some(0), "{}", String::from_utf8_lossy(&r.stderr));
            assert!(r.stderr.is_empty());
            let a = answers(&r.stdout);
            assert_eq!(a.len(), 2);
            assert_eq!(hello_labels(&a[0]), vec!["PER", "LOC"]);
            let s = spans_of(&a[1], 42);
            assert_eq!(s.len(), 2);
            assert_eq!((s[0].start, s[0].end, s[0].label.as_str()), (13, 25, "PER"));
            assert_eq!(&text[s[0].start..s[0].end], "Søren Ærø");
            assert_eq!(&text[s[1].start..s[1].end], "Aarhus");
        }

        #[test]
        fn errors_never_echo_text() {
            if !landlock_or_skip("errors_never_echo_text") {
                return;
            }
            let (_d, p) = phrases();
            let mut input = detect_line(1, &format!("{RARE} {}", "a".repeat(MAX_TEXT)));
            input.extend(
                format!("{{\"op\":\"detect\",\"id\":2,\"text\":\"{RARE}\",\"x\":1}}\n").bytes(),
            );
            input.extend(format!("{RARE} not json\n").bytes());
            let mut long = format!("{{\"op\":\"detect\",\"id\":3,\"text\":\"{RARE}").into_bytes();
            long.resize(MAX_LINE + 10, b'a');
            long.extend(b"\"}\n");
            input.extend(long);
            for extra in [&[][..], &["--panic-in-detect"][..]] {
                let r = run_helper(FAKE, &args(&p, extra), &input);
                assert_eq!(r.code, Some(0), "{extra:?}");
                let out = String::from_utf8_lossy(&r.stdout);
                let err = String::from_utf8_lossy(&r.stderr);
                assert!(!out.contains(RARE) && !out.contains("Ærøskøbing"), "{out}");
                assert!(err.is_empty(), "{err}");
                let a = answers(&r.stdout);
                assert_eq!(a.len(), 5);
                error_of(&a[1], 1);
                error_of(&a[2], 0);
                error_of(&a[3], 0);
                error_of(&a[4], 0);
            }
            // A detect that panics (text in the panic message) answers an
            // error and prints nothing: the silent panic hook.
            let r = run_helper(
                FAKE,
                &args(&p, &["--panic-in-detect"]),
                &detect_line(5, RARE),
            );
            assert_eq!(r.code, Some(0));
            assert!(
                r.stderr.is_empty(),
                "{}",
                String::from_utf8_lossy(&r.stderr)
            );
            let a = answers(&r.stdout);
            assert_eq!(error_of(&a[1], 5), "detection failed");
        }

        #[test]
        fn uncaught_panic_prints_nothing() {
            if !landlock_or_skip("uncaught_panic_prints_nothing") {
                return;
            }
            let (_d, p) = phrases();
            // A panic outside every catch_unwind, its message the request
            // text: the process dies (101) and stderr stays empty.
            let r = run_helper(
                FAKE,
                &args(&p, &["--panic-uncaught"]),
                &detect_line(6, RARE),
            );
            assert_eq!(r.code, Some(101));
            assert!(
                r.stderr.is_empty(),
                "{}",
                String::from_utf8_lossy(&r.stderr)
            );
            assert!(!String::from_utf8_lossy(&r.stdout).contains(RARE));
        }
    }
}
