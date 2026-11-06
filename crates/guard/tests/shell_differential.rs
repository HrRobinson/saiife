//! Differential check: the guard's here-document handling versus the shells
//! actually installed. Every shell must satisfy "no bypass": if it ran the
//! marker command, the engine must deny the line. For bash (any version),
//! exact agreement is required too: ran == denied. For other shells an
//! over-deny (engine denies, shell did not run the marker) is tolerated only
//! for the cases in `KNOWN_NON_BASH_OVER_DENIES`. The marker is a harmless
//! `touch ran` executed with a tempdir as the working directory.

use std::process::Command;

use saiifeguard::engine::{Decision, Engine};
use saiifeguard::pack::load_pack_str;

const PACK: &str = r#"
[pack]
id = "test.touch"
name = "Touch"
triggers = ["touch"]

[[deny]]
pattern = '^touch'
reason = "marker command"
"#;

const TEST_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

fn engine() -> Engine {
    let mut warnings = Vec::new();
    let pack = load_pack_str("<shell_differential>", PACK, &mut warnings).expect("pack loads");
    assert!(warnings.is_empty(), "pack warnings: {warnings:?}");
    Engine::new(vec![pack]).with_budget(TEST_BUDGET)
}

/// Cases where zsh 5.9 and dash end the here-document differently from bash:
/// they do not stop at an `EOF)`-style line, so the rest is body and the
/// marker never runs, while the engine (following bash) denies. Over-denying
/// is the safe direction, so it is allowed (and noted) for non-bash shells.
const KNOWN_NON_BASH_OVER_DENIES: [&str; 3] = [
    "x=$(cat <<EOF\nhi\nEOF)\ntouch ran",
    "x=$(cat <<'EOF'\na\nEOF )\ntouch ran",
    "x=$(cat <<EOF\nEOF x)\ntouch ran\nEOF\n)",
];

fn cases() -> Vec<String> {
    [
        // marker inside a body (data, never runs)
        "x=$(cat <<EOF\ntouch ran\nEOF\n)",
        "x=$(cat <<'EOF'\ntouch ran\nEOF\n)",
        "x=$(cat <<\"EOF\"\ntouch ran\nEOF\n)",
        "cat <<EOF\ntouch ran\nEOF",
        // marker right after the body
        "x=$(cat <<EOF\nhi\nEOF\n)\ntouch ran",
        "x=$(cat <<EOF\nhi\nEOF)\ntouch ran",
        "x=$(cat <<'EOF'\na\nEOF )\ntouch ran",
        "cat <<EOF\nhi\nEOF\ntouch ran",
        // dashed delimiter with tab-indented body and terminator
        "x=$(cat <<-EOF\n\ttouch ran\n\tEOF\n)",
        "x=$(cat <<-EOF\n\thi\n\tEOF\n)\ntouch ran",
        "cat <<-'EOF'\n\ttouch ran\n\tEOF\ntouch ran",
        // two here-documents on one line
        "cat <<A; cat <<B\nx\nA\ntouch ran\nB",
        "x=$(cat <<A <<B\none\nA\ntwo\nB\n)\ntouch ran",
        "cat <<A; cat <<B\nx\nA\ny\nB\ntouch ran",
        // backticks
        "x=`cat <<EOF\ntouch ran\nEOF\n`",
        "x=`cat <<EOF\nhi\nEOF\n`\ntouch ran",
        // body line that merely starts with the delimiter
        "x=$(cat <<EOF\nEOF x)\ntouch ran\nEOF\n)",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn candidate_shells() -> Vec<String> {
    let mut paths: Vec<std::path::PathBuf> = [
        "/bin/bash",
        "/usr/bin/bash",
        "/bin/sh",
        "/bin/zsh",
        "/usr/bin/zsh",
    ]
    .iter()
    .map(std::path::PathBuf::from)
    .collect();
    // `bash` on PATH.
    if let Ok(path) = std::env::var("PATH") {
        paths.extend(std::env::split_paths(&path).map(|d| d.join("bash")));
    }
    // One run per real binary.
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for p in paths {
        if let Ok(real) = p.canonicalize() {
            if real.is_file() && seen.insert(real) {
                out.push(p.to_string_lossy().into_owned());
            }
        }
    }
    out
}

fn version_line(shell: &str) -> String {
    Command::new(shell)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .next()
                .map(str::to_string)
        })
        .unwrap_or_else(|| "<unknown version>".to_string())
}

#[test]
fn heredoc_matches_installed_shells() {
    let shells = candidate_shells();
    if shells.is_empty() {
        println!("no shells found; skipped");
        return;
    }
    let e = engine();
    let cases = cases();
    for tolerated in KNOWN_NON_BASH_OVER_DENIES {
        assert!(
            cases.iter().any(|c| c == tolerated),
            "KNOWN_NON_BASH_OVER_DENIES entry is not in cases(): {tolerated:?}"
        );
    }
    // Tolerated cases must stay in the safe (over-deny) direction.
    for tolerated in KNOWN_NON_BASH_OVER_DENIES {
        assert!(
            matches!(e.evaluate(tolerated), Decision::Deny { .. }),
            "tolerated case no longer denied by the engine: {tolerated:?}"
        );
    }
    // Startup files must never run from the real home.
    let home = tempfile::tempdir().expect("home tempdir");
    let mut failures = Vec::new();
    for shell in &shells {
        let version = version_line(shell);
        let is_bash = version.contains("bash");
        for (n, case) in cases.iter().enumerate() {
            let tmp = tempfile::tempdir().expect("tempdir");
            if let Err(err) = Command::new(shell)
                .arg("-c")
                .arg(case)
                .current_dir(tmp.path())
                .env("HOME", home.path())
                .env("ZDOTDIR", home.path())
                .env_remove("BASH_ENV")
                .env_remove("ENV")
                .output()
            {
                println!("note: {shell} cannot be executed ({err}); skipped");
                break;
            }
            let ran = tmp.path().join("ran").exists();
            let denied = matches!(e.evaluate(case), Decision::Deny { .. });
            if ran && !denied {
                // Hard invariant on every shell: no bypass.
                failures.push(format!(
                    "{shell} ({version}): BYPASS, shell ran marker but engine allows\n  case: {case:?}"
                ));
            } else if !ran && denied {
                if is_bash {
                    failures.push(format!(
                        "{shell} ({version}): bash over-deny\n  case: {case:?}"
                    ));
                } else if KNOWN_NON_BASH_OVER_DENIES.contains(&case.as_str()) {
                    println!("note: {shell} over-denies case {n}: {case:?}");
                } else {
                    failures.push(format!(
                        "{shell} ({version}): unlisted non-bash over-deny\n  case: {case:?}"
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "mismatches:\n{}", failures.join("\n"));
}

/// Reserved words in command position, against bash itself: the marker runs
/// exactly when the engine denies. The flag is false for forms bash 3.2
/// (macOS's `/bin/bash`) does not have.
const RESERVED_WORD_CASES: &[(&str, bool)] = &[
    // These run the marker.
    ("! touch ran", true),
    ("! ! touch ran", true),
    ("! time touch ran", true),
    ("time ! touch ran", true),
    ("time -p ! touch ran", true),
    ("true && ! touch ran", true),
    ("(! touch ran)", true),
    ("!(touch ran)", true),
    ("{ ! touch ran; }", true),
    ("! { touch ran; }", true),
    ("sh -c '! touch ran'", true),
    ("! FOO=1 touch ran", true),
    ("if ! touch ran; then :; fi", true),
    ("if touch ran; then :; fi", true),
    ("while ! touch ran; do break; done", true),
    ("while touch ran; do break; done", true),
    ("until touch ran; do break; done", true),
    ("if true; then ! touch ran; fi", true),
    ("$(true) touch ran", true),
    ("$unset_name touch ran", true),
    ("$(true) $(touch ran)", true),
    ("X=$(true) $(touch ran)", true),
    ("X=$(touch ran) Y=1", true),
    ("$! touch ran", true),
    ("${x:-${y}} touch ran", true),
    ("\"$@\" touch ran", true),
    ("\"${x[@]}\" touch ran", true),
    ("{,} touch ran", true),
    ("$v env $v env touch ran", true),
    ("time if touch ran; then :; fi", true),
    ("set -- a; for x do touch ran; done", true),
    ("for ((i=0;i<1;i++)) do touch ran; done", true),
    ("! bash <<EOF\ntouch ran\nEOF", true),
    ("time ! bash <<EOF\ntouch ran\nEOF", true),
    ("if bash <<EOF\ntouch ran\nEOF\nthen :; fi", true),
    ("if true; then bash <<EOF\ntouch ran\nEOF\nfi", true),
    ("time -- ! touch ran", false),
    ("coproc touch ran; wait", false),
    ("time -p -- ! touch ran", false),
    // These do not.
    (">out ! touch ran", true),
    ("!touch ran", true),
    ("\"!\" touch ran", true),
    ("\\! touch ran", true),
    ("FOO=1 ! touch ran", true),
    ("env ! touch ran", true),
    ("echo ! touch ran", true),
    ("\"if\" touch ran", true),
    ("echo if touch ran", true),
    ("\"$(true)\" touch ran", true),
    ("\"$x\" touch ran", true),
    ("\"$*\" touch ran", true),
    ("\"${x[*]}\" touch ran", true),
    ("! cat <<EOF\ntouch ran\nEOF", true),
];

/// Cases bash before 4 does not run and newer bash does: 3.2.57 (macOS's
/// `/bin/bash` and `/bin/sh`) leaves `! ! touch ran` without running `touch`.
/// The guard must keep denying them, because newer bash runs the command, so
/// there a deny with nothing run is an accepted over-deny, on the safe side.
const OVER_DENIED_BEFORE_BASH_4: &[&str] = &["! ! touch ran"];

/// Does the engine's verdict on `case` disagree with what the shell did? A
/// command that ran and was not denied always does. A listed case on old bash
/// only has to stay denied.
fn is_mismatch(old_bash: bool, case: &str, ran: bool, denied: bool) -> bool {
    if old_bash && OVER_DENIED_BEFORE_BASH_4.contains(&case) {
        return !denied;
    }
    ran != denied
}

#[test]
fn only_the_listed_over_deny_is_accepted_on_old_bash() {
    let listed = OVER_DENIED_BEFORE_BASH_4[0];
    assert!(!is_mismatch(true, listed, false, true));
    // Ran and not denied fails, and so does no longer denying it.
    assert!(is_mismatch(true, listed, true, false));
    assert!(is_mismatch(true, listed, false, false));
    // Newer bash runs it, so there the two must agree.
    assert!(is_mismatch(false, listed, false, true));
    // Any other case still has to match on old bash.
    assert!(is_mismatch(true, "! touch ran", false, true));
    assert!(is_mismatch(true, "! touch ran", true, false));
}

#[test]
fn reserved_words_match_bash() {
    let e = engine();
    let home = tempfile::tempdir().expect("home tempdir");
    let mut failures = Vec::new();
    for shell in candidate_shells() {
        let version = version_line(&shell);
        if !version.contains("bash") {
            continue;
        }
        let old = version.contains("version 3.");
        for (case, in_old) in RESERVED_WORD_CASES {
            if old && !in_old {
                continue;
            }
            let tmp = tempfile::tempdir().expect("tempdir");
            let run = Command::new(&shell)
                .arg("-c")
                .arg(case)
                .current_dir(tmp.path())
                .env("HOME", home.path())
                .env_remove("BASH_ENV")
                .env_remove("ENV")
                .output();
            if let Err(err) = run {
                println!("note: {shell} cannot be executed ({err}); skipped");
                break;
            }
            let ran = tmp.path().join("ran").exists();
            let denied = matches!(e.evaluate(case), Decision::Deny { .. });
            if is_mismatch(old, case, ran, denied) {
                failures.push(format!(
                    "{shell} ({version}): ran={ran} denied={denied}\n  case: {case:?}"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "mismatches:\n{}", failures.join("\n"));
}

/// Lines a shell runs that are not where a command starts, against bash
/// itself: `find -exec`, a pipe or a here-string into a shell, a `trap`
/// action, a backslash-newline inside a word, a substitution in a `${…}`
/// default. The flag says whether bash runs the marker; the engine must deny
/// exactly those, except the listed over-denies.
const HIDDEN_LINE_CASES: &[(&str, bool)] = &[
    // These run the marker.
    (r"find . -maxdepth 0 -exec touch ran \;", true),
    ("find . -maxdepth 0 -execdir touch ran ';'", true),
    ("find . -maxdepth 0 -exec touch ran {} +", true),
    (r"echo y | find . -maxdepth 0 -ok touch ran \;", true),
    (r"find . -maxdepth 0 -exec sh -c 'touch ran' \;", true),
    ("echo 'touch ran' | sh", true),
    ("echo 'touch ran' | bash", true),
    ("echo touch ran | bash -s", true),
    ("printf 'touch ran' | sh", true),
    ("echo 'touch ran' |& sh", true),
    ("echo \"echo 'touch ran' | sh\" | sh", true),
    ("bash <<< 'touch ran'", true),
    ("<<< 'touch ran' bash", true),
    ("trap 'touch ran' EXIT", true),
    ("trap -- 'touch ran' EXIT", true),
    ("tou\\\nch ran", true),
    ("\"tou\\\nch\" ran", true),
    ("touch \\\nran", true),
    ("echo ${x:-$(touch ran)}", true),
    ("echo \"${x:-$(touch ran)}\"", true),
    ("echo ${x:-`touch ran`}", true),
    ("echo ${x:-${y:-$(touch ran)}}", true),
    ("echo ${x:-\"$(touch ran)\"}", true),
    ("echo \"${x:-'$(touch ran)'}\"", true),
    (r"find . -maxdepth 0 -exec sh -c -exec 'touch ran' \;", true),
    (r"find . -maxdepth 0 -exec env X=-exec touch ran \;", true),
    ("echo 'touch ran' | { true; sh; }", true),
    ("echo 'touch ran' | ( case a in a) sh;; esac )", true),
    ("echo 'touch ran' | bash /dev/stdin", true),
    ("echo 'touch ran' | sh /proc/self/fd/0", true),
    ("echo 'touch ran' | sh //dev/stdin", true),
    ("echo 'touch ran' | sh /dev/./stdin", true),
    ("echo 'touch ran' | sh /dev/fd//0", true),
    ("echo 'touch ran' | sh -", true),
    ("echo 'touch ran' | bash -c 'sh'", true),
    ("bash -c 'sh' <<< 'touch ran'", true),
    (r"echo 'touch ran' | find . -maxdepth 0 -exec sh \;", true),
    ("echo 'touch ran' | if true; then sh; fi", true),
    ("echo 'touch ran' | case a in a) sh;; esac", true),
    ("echo 'touch ran' | until false; do sh; break; done", true),
    ("echo 'touch ran' | for i in 1; do sh; done", true),
    (
        "echo 'touch ran' | if true; then if true; then :; fi; sh; fi",
        true,
    ),
    ("if true; then sh; fi <<< 'touch ran'", true),
    // A block after `time -p`, `coproc [NAME]` or `function NAME [()]`, or
    // a `}` that is an argument, leaves the pipe feeding the block around.
    (
        "echo 'touch ran' | { time -p if true; then :; fi; sh; }",
        true,
    ),
    (
        "echo 'touch ran' | if true; then time -p if true; then :; fi; sh; fi",
        true,
    ),
    (
        "echo 'touch ran' | if true; then time -p -- if true; then :; fi; sh; fi",
        true,
    ),
    (
        "echo 'touch ran' | if true; then coproc if true; then :; fi; sh; fi",
        true,
    ),
    (
        "echo 'touch ran' | if true; then coproc C if true; then :; fi; sh; fi",
        true,
    ),
    (
        "echo 'touch ran' | while true; do coproc while false; do :; done; sh; break; done",
        true,
    ),
    (
        "echo 'touch ran' | while true; do coproc W while false; do :; done; sh; break; done",
        true,
    ),
    (
        "echo 'touch ran' | case a in a) coproc case b in b) :;; esac; sh;; esac",
        true,
    ),
    (
        "echo 'touch ran' | if true; then function f () if true; then :; fi; sh; fi",
        true,
    ),
    (
        "echo 'touch ran' | if true; then function f if true; then :; fi; sh; fi",
        true,
    ),
    (
        "echo 'touch ran' | if true; then function f () { :; }; sh; fi",
        true,
    ),
    ("echo 'touch ran' | { echo }; sh; }", true),
    ("echo 'touch ran' | { echo 'if'; sh; }", true),
    // These do not.
    ("echo 'touch ran' | { time -p cat; }", false),
    (
        "printf 'touch ran' | while read l; do if [ -n \"$l\" ]; then echo \"$l\"; fi; done",
        false,
    ),
    ("echo 'touch ran' | { echo 'if'; }; sh", false),
    (
        "echo 'touch ran' | { time -p if true; then cat; fi; }; sh",
        false,
    ),
    ("echo 'touch ran' | if true; then echo if; fi; sh", false),
    (
        "echo 'touch ran' | while true; do echo done; break; done; sh",
        false,
    ),
    ("echo 'touch ran' | (cat >/dev/null; sh)", false),
    ("echo 'touch ran' | { cat; }; sh -c 'echo hi'", false),
    ("echo 'touch ran' | bash -c 'cat'", false),
    (
        "printf '%s\\n' a b | while read l; do echo \"$l\"; done",
        false,
    ),
    ("echo 'touch ran' | if true; then cat; fi", false),
    (r"find . -maxdepth 0 -exec echo touch ran \;", false),
    ("find . -maxdepth 0 -exec touch ran", false),
    ("echo 'echo touch ran' | sh", false),
    ("echo 'touch ran' | sh -c 'cat'", false),
    ("echo 'touch ran' | grep touch", false),
    ("bash -c 'echo hi' <<< 'touch ran'", false),
    ("cat <<< 'touch ran'", false),
    ("trap 'touch ran'", false),
    ("trap 'touch ran' INT", false),
    ("'tou\\\nch' ran", false),
    ("echo ${x:-'$(touch ran)'}", false),
    ("echo '${x:-$(touch ran)}'", false),
];

/// A trap for a signal that never comes: its action does not run here, but
/// it could. A shell in a group after a command that may read the pipe
/// first (`cat`): what is left for it is not known. A block whose openers and
/// closers do not balance (an argument `if` or `done`): the pipe is taken to
/// feed the rest of the line. Denied, on the safe side.
const HIDDEN_LINE_OVER_DENIES: &[&str] = &[
    "trap 'touch ran' INT",
    "echo 'touch ran' | (cat >/dev/null; sh)",
    "echo 'touch ran' | if true; then echo if; fi; sh",
    "echo 'touch ran' | while true; do echo done; break; done; sh",
];

#[test]
fn hidden_lines_match_bash() {
    let e = engine();
    let home = tempfile::tempdir().expect("home tempdir");
    let mut failures = Vec::new();
    for shell in candidate_shells() {
        let version = version_line(&shell);
        // bash 4 and later: `|&` and here-strings in the forms used here.
        if !version.contains("bash") || version.contains("version 3.") {
            continue;
        }
        for (case, runs) in HIDDEN_LINE_CASES {
            let tmp = tempfile::tempdir().expect("tempdir");
            let run = Command::new(&shell)
                .arg("-c")
                .arg(case)
                .current_dir(tmp.path())
                .env("HOME", home.path())
                .env_remove("BASH_ENV")
                .env_remove("ENV")
                .output();
            if let Err(err) = run {
                println!("note: {shell} cannot be executed ({err}); skipped");
                break;
            }
            let ran = tmp.path().join("ran").exists();
            let denied = matches!(e.evaluate(case), Decision::Deny { .. });
            let over_deny = HIDDEN_LINE_OVER_DENIES.contains(case) && denied && !ran;
            if ran != *runs || (ran != denied && !over_deny) {
                failures.push(format!(
                    "{shell} ({version}): ran={ran} (listed {runs}) denied={denied}\n  case: {case:?}"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "mismatches:\n{}", failures.join("\n"));
}
