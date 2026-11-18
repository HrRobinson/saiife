//! `saiife-ner`: the sandboxed local name detector (plan 46, R46-1).
//!
//! Order: the silent panic hook (a panic message can quote request text or
//! WordPiece ids) → arguments (R46-4; bad → usage, exit 2) → resource limits
//! and the sandbox (R46-6: AS 4 GiB, 32 open files, no file written, no new
//! process or thread; Landlock read-only on the three files and nothing
//! else; no network; the Ner seccomp allowlist; failure → a fixed stderr
//! line, exit 5) → read the three files (each capped) → check each SHA-256
//! against its argument before anything is parsed (mismatch → stderr
//! `hash mismatch for model|vocab|labels`, exit 3) → load the model (failure
//! → `{"t":"error","id":0,"error":"cannot load the model"}`, exit 4) →
//! hello, then one answer per request until EOF (exit 0).
//!
//! It never logs: no logger is installed (tract's `log` calls are no-ops),
//! stderr carries only the fixed lines above.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    use saiife_shield::ner_proto::encode;
    use saiife_shield_ner::serve::{
        confine, error_answer, install_silent_panic_hook, load_checked, serve, LoadFailure,
        NerArgs, ERR_LOAD, NER_USAGE,
    };
    use std::io::Write;
    use std::process::ExitCode;

    install_silent_panic_hook();
    let Ok(args) = NerArgs::parse(std::env::args_os().skip(1)) else {
        eprintln!("{NER_USAGE}");
        return ExitCode::from(2);
    };
    if let Err(e) = confine(&[&args.model, &args.vocab, &args.labels]) {
        // SandboxError texts are fixed and hold no values.
        eprintln!("saiife-ner: {e}");
        return ExitCode::from(5);
    }
    let model = match load_checked(&args) {
        Ok(m) => m,
        Err(LoadFailure::Hash(name)) => {
            eprintln!("hash mismatch for {name}");
            return ExitCode::from(3);
        }
        Err(LoadFailure::Load) => {
            let mut out = std::io::stdout().lock();
            let _ = out.write_all(&encode(&error_answer(0, ERR_LOAD)));
            let _ = out.flush();
            return ExitCode::from(4);
        }
    };
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    match serve(&model, &mut stdin.lock(), &mut stdout.lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(1),
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("saiife-ner runs on Linux only");
    std::process::ExitCode::from(2)
}
