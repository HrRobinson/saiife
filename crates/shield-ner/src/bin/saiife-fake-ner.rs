//! `saiife-fake-ner --phrases <file>` (feature `fake`, tests only): the
//! `saiife-ner/1` protocol with [`PhraseDetector`] instead of a model,
//! confined the same way as `saiife-ner` (resource limits, Landlock
//! read-only on the phrases file, no network, the Ner seccomp allowlist).
//!
//! Test switches (this binary is never shipped): `--panic-in-detect` makes
//! every detect panic with the request text as its message (answered
//! `detection failed`); `--panic-uncaught` reads one request line and panics
//! with it outside every `catch_unwind`. Both prove the silent panic hook.
//!
//! [`PhraseDetector`]: saiife_shield_ner::serve::PhraseDetector

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    use saiife_shield::ner_proto::{encode, WireSpan};
    use saiife_shield_ner::serve::{
        confine, error_answer, install_silent_panic_hook, serve, Detect, PhraseDetector, ERR_LOAD,
    };
    use saiife_shield_ner::NerError;
    use std::io::{BufRead, Write};
    use std::path::PathBuf;
    use std::process::ExitCode;

    struct Panicking(PhraseDetector);
    impl Detect for Panicking {
        fn detect(&self, text: &str) -> Result<Vec<WireSpan>, NerError> {
            panic!("{text}");
        }
        fn labels(&self) -> Vec<String> {
            self.0.labels()
        }
    }

    install_silent_panic_hook();
    let mut phrases: Option<PathBuf> = None;
    let (mut panic_in_detect, mut panic_uncaught) = (false, false);
    let mut it = std::env::args_os().skip(1);
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("--phrases") if phrases.is_none() => phrases = it.next().map(PathBuf::from),
            Some("--panic-in-detect") => panic_in_detect = true,
            Some("--panic-uncaught") => panic_uncaught = true,
            _ => phrases = None,
        }
    }
    let Some(phrases) = phrases else {
        eprintln!("usage: saiife-fake-ner --phrases <file>");
        return ExitCode::from(2);
    };
    if let Err(e) = confine(&[&phrases]) {
        eprintln!("saiife-fake-ner: {e}");
        return ExitCode::from(5);
    }
    let Ok(d) = PhraseDetector::from_file(&phrases) else {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(&encode(&error_answer(0, ERR_LOAD)));
        let _ = out.flush();
        return ExitCode::from(4);
    };
    let stdin = std::io::stdin();
    if panic_uncaught {
        let mut line = String::new();
        let _ = stdin.lock().read_line(&mut line);
        panic!("{line}");
    }
    let stdout = std::io::stdout();
    let r = if panic_in_detect {
        serve(&Panicking(d), &mut stdin.lock(), &mut stdout.lock())
    } else {
        serve(&d, &mut stdin.lock(), &mut stdout.lock())
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(1),
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("saiife-fake-ner runs on Linux only");
    std::process::ExitCode::from(2)
}
