//! Transparent-prefix command unwrapping.
//!
//! A handful of commands merely wrap another command without changing its
//! meaning for our purposes: `command rm -rf /`, `env rm -rf /`, `nohup rm
//! -rf /` all execute `rm -rf /` exactly as if the wrapper weren't there.
//! `sudo <flags> rm -rf /` is the same shape — it just has a much larger
//! option surface — so it is unwrapped structurally here too, the same as
//! the others: the engine judges the *effective* command's argv, not the
//! wrapper's, so no pack needs to know about any of these. (Packs still
//! carry a redundant `(?:sudo\s+)?` regex prefix from before this fix; it is
//! harmless dead weight now that unwrapping is authoritative — it only ever
//! matches the `sudo <cmd>` shape unwrapping already peels off.)
//!
//! Handled here (transparent prefixes, returning a sub-slice of the same
//! segment): `command`, `env` (skipping leading `VAR=val` assignments and
//! flags), `nohup`, `nice` (skipping an optional `-n VALUE` or `-VALUE`
//! niceness flag), `stdbuf`, `ionice` (skipping leading `-`-prefixed flags),
//! `sudo` (skipping leading `VAR=val` assignments and its own options,
//! including arg-taking ones like `-u root`/`--user root`/`--user=root`),
//! `time` (`-p` and GNU `-o`/`-f` value options), and the positional-skip
//! wrappers `timeout` (options then one duration positional), `chroot`
//! (options then one NEWROOT positional), and `flock` (options then one
//! lockfile positional, prefix form only). Full-path invocations
//! (`/usr/bin/time`) are recognized.
//!
//! Two more wrappers are handled *elsewhere*, not as transparent prefixes:
//! `su -c '…'` and `watch …` route through `crate::payload` and the engine's
//! inline-payload recursion, because the wrapped command is a string the
//! shell re-parses rather than a leading sub-slice (and `su`'s first operand
//! is a username, which a blind prefix-skip would misread).
//!
//! Deliberately not exhaustive — two documented gaps remain: `xargs` (its
//! catastrophic operand arrives on stdin from the producer, invisible to a
//! static scan) and the `flock … -c 'STRING'` sub-form. See the design doc's
//! "Known limitations".

use crate::lexer::Word;

/// Command names that transparently wrap another command. Matched
/// case-insensitively against each word's text, mirroring the case-fold
/// applied to argv[0] elsewhere in the pipeline (macOS's case-insensitive
/// filesystem means `COMMAND rm -rf /` finds the same binary as `command`).
const TRANSPARENT_PREFIXES: &[&str] =
    &[
        "command", "env", "nohup", "nice", "stdbuf", "ionice", "sudo", "time", "timeout", "chroot",
        "flock",
    ];

/// `sudo` short options that take a value, e.g. `-u root`. Bundled/attached
/// forms (`-uroot`) are also handled — see `unwrap_transparent_prefix`.
const SUDO_ARG_TAKING_SHORT: &[char] = &['u', 'g', 'p', 'C', 'h', 'r', 't', 'U', 'R', 'D'];

/// `sudo` long options that take a value when not given in `--opt=value`
/// form (that form is handled generically — the whole token is one word
/// either way).
const SUDO_ARG_TAKING_LONG: &[&str] = &[
    "user",
    "group",
    "prompt",
    "chdir",
    "host",
    "role",
    "type",
    "close-from",
    "other-user",
    "chroot",
    "directory",
];

/// Peel any number of transparent wrapper commands off the front of a
/// segment's words, returning the slice starting at the effective command.
/// Each iteration of the outer loop consumes at least the wrapper's own
/// name, so this is bounded by the segment's length and cannot loop
/// unboundedly on adversarial input (no risk to the latency budget).
pub fn unwrap_transparent_prefix(seg: &[Word]) -> &[Word] {
    let mut rest = seg;
    loop {
        let Some(head) = rest.first() else {
            return rest;
        };
        // Strip any leading directory (`/usr/bin/time` -> `time`) and
        // case-fold before matching — the same canonicalization
        // `normalize::build_argv` applies to argv[0], but done here because
        // unwrapping runs on the raw segment *before* that normalization.
        // Skip-only, so this can only ever catch more, never manufacture a
        // false positive.
        let lowered = head.text.to_ascii_lowercase();
        let name = strip_program_dir(&lowered);
        if !TRANSPARENT_PREFIXES.contains(&name) {
            return rest;
        }
        rest = &rest[1..];
        match name {
            "env" => {
                // `env FOO=bar -i rm -rf /` — skip leading assignments and
                // env's own flags to reach the real command.
                while rest
                    .first()
                    .map(|w| is_env_assignment(&w.text) || w.text.starts_with('-'))
                    .unwrap_or(false)
                {
                    rest = &rest[1..];
                }
            }
            "nice" => {
                if let Some(w) = rest.first() {
                    if w.text == "-n" {
                        rest = &rest[1..]; // consume "-n"
                        if !rest.is_empty() {
                            rest = &rest[1..]; // consume its value
                        }
                    } else if is_dash_numeric(&w.text) {
                        rest = &rest[1..]; // consume "-<niceness>"
                    }
                }
            }
            "stdbuf" | "ionice" | "command" => {
                while rest.first().map(|w| w.text.starts_with('-')).unwrap_or(false) {
                    rest = &rest[1..];
                }
            }
            "sudo" => rest = skip_sudo_options(rest),
            "time" => {
                // `time [-p] CMD` (shell builtin) and GNU `/usr/bin/time
                // [OPTIONS] CMD` — value-taking `-o FILE`/`-f FMT` and their
                // `--output`/`--format` long forms; no positionals precede
                // the command.
                rest = skip_options_then_positionals(rest, &['o', 'f'], &["output", "format"], 0, None);
            }
            "timeout" => {
                // `timeout [OPTIONS] DURATION CMD` — value-taking
                // `-s SIGNAL`/`-k DURATION` (and `--signal`/`--kill-after`),
                // then exactly one DURATION positional gated by a duration
                // shape so a malformed `timeout rm …` never eats a command.
                rest = skip_options_then_positionals(
                    rest,
                    &['s', 'k'],
                    &["signal", "kill-after"],
                    1,
                    Some(is_duration_shape),
                );
            }
            "chroot" => {
                // `chroot [OPTIONS] NEWROOT [CMD]` — GNU chroot's `--userspec`
                // and `--groups` accept their value either attached
                // (`--userspec=root:root`) or as a separate following token
                // (`--userspec root:root`); BSD/macOS chroot additionally has
                // short value options `-u`/`-g`/`-G`/`-U`. Then exactly one
                // NEWROOT positional precedes the command. (A recursive wipe
                // of the chroot's own root is still the catastrophe class we
                // block — see the design's DECISION 5.)
                rest = skip_options_then_positionals(
                    rest,
                    &['u', 'g', 'G', 'U'],
                    &["userspec", "groups"],
                    1,
                    None,
                );
            }
            "flock" => {
                // `flock [OPTIONS] <LOCKFILE|DIR|FD> CMD` (the dominant prefix
                // form) — value-taking `-w SECONDS`/`-E CODE` (and `--timeout`/
                // `--conflict-exit-code`), then one lock-target positional.
                // The `flock … -c 'STRING'` sub-form is deferred (design
                // DECISION 4): it interleaves an inline payload after the
                // positional and is a documented gap, not handled here.
                rest = skip_options_then_positionals(
                    rest,
                    &['w', 'E'],
                    &["timeout", "conflict-exit-code"],
                    1,
                    None,
                );
            }
            _ => {}
        }
    }
}

/// Skip past `sudo`'s own leading `VAR=val` assignments and options —
/// including arg-taking ones (`-u root`, `--user root`, `--user=root`, and
/// the attached short form `-uroot`) — to reach the effective command.
/// Bounded by `seg`'s length: each iteration consumes at least one token.
fn skip_sudo_options(mut rest: &[Word]) -> &[Word] {
    loop {
        let Some(w) = rest.first() else { return rest };
        let tok = w.text.as_str();

        if is_env_assignment(tok) {
            rest = &rest[1..];
            continue;
        }
        if tok == "--" {
            // End of options: whatever follows is the command, even if it
            // looks flag-shaped.
            return &rest[1..];
        }
        if let Some(long) = tok.strip_prefix("--") {
            if long.is_empty() {
                return &rest[1..]; // bare "--" already handled above
            }
            let name = long.split('=').next().unwrap_or(long);
            if long.contains('=') || !SUDO_ARG_TAKING_LONG.contains(&name) {
                // `--user=root` (value attached) or a boolean/unrecognized
                // long flag: the whole token is consumed either way.
                rest = &rest[1..];
            } else {
                // `--user root`: consume the flag and its separate value.
                rest = &rest[1..];
                if !rest.is_empty() {
                    rest = &rest[1..];
                }
            }
            continue;
        }
        if let Some(short) = tok.strip_prefix('-') {
            if short.is_empty() {
                return rest; // bare "-": not a recognized option, stop here
            }
            let first = short.chars().next().unwrap();
            rest = &rest[1..];
            if SUDO_ARG_TAKING_SHORT.contains(&first) && short.len() == 1 {
                // `-u root`: the value is a separate token.
                if !rest.is_empty() {
                    rest = &rest[1..];
                }
            }
            // Otherwise: a boolean flag, a bundle of boolean flags, or an
            // arg-taking flag with its value attached (`-uroot`) — the one
            // token already consumed above covers it.
            continue;
        }
        return rest; // not an assignment or an option: this is the command
    }
}

/// Skip a wrapper's leading options and then up to `positionals` operand
/// tokens, returning the slice starting at the effective wrapped command.
///
/// Shared by the positional-skip wrappers (`timeout`, `chroot`, `flock`) and
/// the pure option-skip case (`time`, with `positionals = 0`). The option
/// phase consumes `-`-prefixed tokens, taking a *separate* following value
/// token for the listed value-taking short (`value_shorts`) and long
/// (`value_longs`) options; attached forms (`-w5`, `--timeout=5`) are a single
/// token and need no special casing. A bare `--` ends the option phase; a
/// bare `-` is treated as the start of the operands. The positional phase then
/// consumes up to `positionals` non-option tokens, each gated by the optional
/// `positional_shape` predicate — if a slot's token fails the predicate it is
/// *not* skipped and the phase stops (used for `timeout`'s duration-shape
/// guard, the sole theoretical false-positive path for a positional skip).
///
/// Bounded by `rest`'s length: every branch consumes at least one token.
fn skip_options_then_positionals<'a>(
    mut rest: &'a [Word],
    value_shorts: &[char],
    value_longs: &[&str],
    positionals: usize,
    positional_shape: Option<fn(&str) -> bool>,
) -> &'a [Word] {
    // Option phase.
    loop {
        let Some(w) = rest.first() else { return rest };
        let tok = w.text.as_str();

        if tok == "--" {
            // End of options: the operands (and then the command) follow.
            rest = &rest[1..];
            break;
        }
        if let Some(long) = tok.strip_prefix("--") {
            // `long` is non-empty (bare "--" handled above).
            let name = long.split('=').next().unwrap_or(long);
            if long.contains('=') || !value_longs.contains(&name) {
                // Attached value (`--timeout=5`) or a boolean/unrecognized
                // long flag: one token either way.
                rest = &rest[1..];
            } else {
                // `--timeout 5`: consume the flag and its separate value.
                rest = &rest[1..];
                if !rest.is_empty() {
                    rest = &rest[1..];
                }
            }
            continue;
        }
        if let Some(short) = tok.strip_prefix('-') {
            if short.is_empty() {
                break; // bare "-": start of operands, not an option.
            }
            let first = short.chars().next().unwrap();
            rest = &rest[1..];
            if short.len() == 1 && value_shorts.contains(&first) {
                // `-w 5`: the value is a separate token. Bundled booleans and
                // attached values (`-w5`) are the single token already
                // consumed above.
                if !rest.is_empty() {
                    rest = &rest[1..];
                }
            }
            continue;
        }
        break; // not an option: the operands begin here.
    }

    // Positional phase: skip up to `positionals` operand tokens.
    for _ in 0..positionals {
        let Some(w) = rest.first() else { break };
        if let Some(pred) = positional_shape {
            if !pred(&w.text) {
                break; // shape guard: leave a non-matching token in place.
            }
        }
        rest = &rest[1..];
    }
    rest
}

/// True if `tok` looks like a `NAME=value` shell-assignment word (`env`'s
/// leading-assignment syntax), not merely any token containing `=`.
fn is_env_assignment(tok: &str) -> bool {
    match tok.find('=') {
        Some(0) | None => false,
        Some(idx) => {
            let name = &tok[..idx];
            name.chars()
                .next()
                .map(|c| c.is_ascii_alphabetic() || c == '_')
                .unwrap_or(false)
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
    }
}

/// Strip a leading directory from a program token (`/usr/bin/time` ->
/// `time`, `time` -> `time`). Mirrors `normalize::strip_program_dir`, applied
/// here so a full-path wrapper invocation is recognized before matching.
fn strip_program_dir(program: &str) -> &str {
    match program.rfind('/') {
        Some(idx) => &program[idx + 1..],
        None => program,
    }
}

/// True if `tok` looks like a GNU `timeout` DURATION: an integer or decimal
/// with an optional `s`/`m`/`h`/`d` unit suffix (`300`, `5s`, `1.5h`).
/// Matches `^\d+(\.\d+)?[smhd]?$`. Used as `timeout`'s positional-shape guard
/// so a malformed `timeout rm …` (no duration) never skips a real command
/// word — the sole theoretical false-positive path for a positional skip.
fn is_duration_shape(tok: &str) -> bool {
    let body = match tok.chars().last() {
        Some(c @ ('s' | 'm' | 'h' | 'd')) => &tok[..tok.len() - c.len_utf8()],
        _ => tok,
    };
    if body.is_empty() {
        return false;
    }
    let mut parts = body.splitn(2, '.');
    let int = parts.next().unwrap_or("");
    if int.is_empty() || !int.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    match parts.next() {
        None => true,
        Some(frac) => !frac.is_empty() && frac.chars().all(|c| c.is_ascii_digit()),
    }
}

/// True for a bare `-<digits>` token, e.g. `nice`'s short-form niceness flag
/// (`nice -10 cmd`).
fn is_dash_numeric(tok: &str) -> bool {
    tok.strip_prefix('-')
        .map(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(text: &str) -> Word {
        Word {
            text: text.to_string(),
            has_substitution: false,
        }
    }

    fn texts(seg: &[Word]) -> Vec<&str> {
        seg.iter().map(|w| w.text.as_str()).collect()
    }

    #[test]
    fn helper_skips_boolean_options_only() {
        let seg = vec![w("-x"), w("-n"), w("rm"), w("-rf"), w("/")];
        assert_eq!(
            texts(skip_options_then_positionals(&seg, &[], &[], 0, None)),
            vec!["rm", "-rf", "/"]
        );
    }

    #[test]
    fn helper_skips_value_taking_short_separate() {
        let seg = vec![w("-w"), w("5"), w("cmd")];
        assert_eq!(
            texts(skip_options_then_positionals(&seg, &['w'], &[], 0, None)),
            vec!["cmd"]
        );
    }

    #[test]
    fn helper_attached_short_value_is_one_token() {
        let seg = vec![w("-w5"), w("cmd")];
        assert_eq!(
            texts(skip_options_then_positionals(&seg, &['w'], &[], 0, None)),
            vec!["cmd"]
        );
    }

    #[test]
    fn helper_skips_value_taking_long_separate_and_attached() {
        let sep = vec![w("--timeout"), w("5"), w("cmd")];
        assert_eq!(
            texts(skip_options_then_positionals(&sep, &[], &["timeout"], 0, None)),
            vec!["cmd"]
        );
        let att = vec![w("--timeout=5"), w("cmd")];
        assert_eq!(
            texts(skip_options_then_positionals(&att, &[], &["timeout"], 0, None)),
            vec!["cmd"]
        );
    }

    #[test]
    fn helper_double_dash_ends_options() {
        let seg = vec![w("-x"), w("--"), w("cmd"), w("-rf")];
        assert_eq!(
            texts(skip_options_then_positionals(&seg, &[], &[], 0, None)),
            vec!["cmd", "-rf"]
        );
    }

    #[test]
    fn helper_skips_one_positional() {
        let seg = vec![w("-x"), w("/tmp/lock"), w("rm"), w("-rf"), w("/")];
        assert_eq!(
            texts(skip_options_then_positionals(&seg, &[], &[], 1, None)),
            vec!["rm", "-rf", "/"]
        );
    }

    #[test]
    fn helper_positional_shape_guard_leaves_non_matching_token() {
        // A positional that fails the shape predicate is NOT skipped.
        let seg = vec![w("rm"), w("-rf"), w("/")];
        assert_eq!(
            texts(skip_options_then_positionals(
                &seg,
                &[],
                &[],
                1,
                Some(is_duration_shape)
            )),
            vec!["rm", "-rf", "/"]
        );
        // A matching one is skipped.
        let seg = vec![w("300"), w("rm"), w("-rf"), w("/")];
        assert_eq!(
            texts(skip_options_then_positionals(
                &seg,
                &[],
                &[],
                1,
                Some(is_duration_shape)
            )),
            vec!["rm", "-rf", "/"]
        );
    }

    #[test]
    fn helper_no_command_after_options_yields_empty() {
        let seg = vec![w("-x"), w("-n")];
        assert!(skip_options_then_positionals(&seg, &[], &[], 0, None).is_empty());
    }

    #[test]
    fn unwraps_time_bare_and_portability_flag() {
        assert_eq!(
            texts(unwrap_transparent_prefix(&[w("time"), w("rm"), w("-rf"), w("/")])),
            vec!["rm", "-rf", "/"]
        );
        assert_eq!(
            texts(unwrap_transparent_prefix(&[
                w("time"),
                w("-p"),
                w("rm"),
                w("-rf"),
                w("/")
            ])),
            vec!["rm", "-rf", "/"]
        );
    }

    #[test]
    fn unwraps_gnu_time_value_options() {
        // -v boolean, -o FILE / -f FMT separate-value forms.
        assert_eq!(
            texts(unwrap_transparent_prefix(&[w("time"), w("-v"), w("rm"), w("-rf"), w("/")])),
            vec!["rm", "-rf", "/"]
        );
        assert_eq!(
            texts(unwrap_transparent_prefix(&[
                w("time"),
                w("-o"),
                w("out.txt"),
                w("rm"),
                w("-rf"),
                w("/")
            ])),
            vec!["rm", "-rf", "/"]
        );
        assert_eq!(
            texts(unwrap_transparent_prefix(&[
                w("time"),
                w("--output=out.txt"),
                w("rm"),
                w("-rf"),
                w("/")
            ])),
            vec!["rm", "-rf", "/"]
        );
    }

    #[test]
    fn unwraps_full_path_wrappers() {
        // Full-path invocation must be recognized the same as the bare name.
        assert_eq!(
            texts(unwrap_transparent_prefix(&[
                w("/usr/bin/time"),
                w("-v"),
                w("rm"),
                w("-rf"),
                w("/")
            ])),
            vec!["rm", "-rf", "/"]
        );
        assert_eq!(
            texts(unwrap_transparent_prefix(&[w("/usr/bin/sudo"), w("rm"), w("-rf"), w("/")])),
            vec!["rm", "-rf", "/"]
        );
        assert_eq!(
            texts(unwrap_transparent_prefix(&[
                w("/usr/bin/timeout"),
                w("5"),
                w("rm"),
                w("-rf"),
                w("/")
            ])),
            vec!["rm", "-rf", "/"]
        );
    }

    #[test]
    fn time_on_benign_command_leaves_it_intact() {
        assert_eq!(
            texts(unwrap_transparent_prefix(&[w("time"), w("-p"), w("make")])),
            vec!["make"]
        );
    }

    #[test]
    fn unwraps_timeout_duration_and_command() {
        assert_eq!(
            texts(unwrap_transparent_prefix(&[
                w("timeout"),
                w("300"),
                w("rm"),
                w("-rf"),
                w("/")
            ])),
            vec!["rm", "-rf", "/"]
        );
        // Suffixed duration.
        assert_eq!(
            texts(unwrap_transparent_prefix(&[w("timeout"), w("5s"), w("rm"), w("-rf"), w("/")])),
            vec!["rm", "-rf", "/"]
        );
    }

    #[test]
    fn unwraps_timeout_with_value_options() {
        for opt in [
            vec![w("-s"), w("KILL"), w("10")],
            vec![w("--signal=KILL"), w("10")],
            vec![w("-k"), w("5"), w("10")],
            vec![w("--kill-after"), w("5"), w("10")],
        ] {
            let mut seg = vec![w("timeout")];
            seg.extend(opt);
            seg.extend([w("rm"), w("-rf"), w("/")]);
            assert_eq!(
                texts(unwrap_transparent_prefix(&seg)),
                vec!["rm", "-rf", "/"],
                "opts {:?}",
                texts(&seg)
            );
        }
    }

    #[test]
    fn timeout_benign_command_left_intact() {
        assert_eq!(
            texts(unwrap_transparent_prefix(&[w("timeout"), w("5"), w("ls")])),
            vec!["ls"]
        );
    }

    #[test]
    fn timeout_no_command_fails_open_without_panic() {
        // bare `timeout`, and `timeout 300` with no command: nothing to run.
        assert!(unwrap_transparent_prefix(&[w("timeout")]).is_empty()
            || texts(unwrap_transparent_prefix(&[w("timeout")])) == vec!["timeout"]);
        assert!(unwrap_transparent_prefix(&[w("timeout"), w("300")]).is_empty());
    }

    #[test]
    fn timeout_non_duration_positional_is_not_skipped() {
        // Malformed `timeout rm -rf /` — `rm` is not duration-shaped, so the
        // duration slot is not consumed; `rm` stays at argv[0] (still caught
        // as a real command by the pack, but proves the shape guard works).
        assert_eq!(
            texts(unwrap_transparent_prefix(&[w("timeout"), w("rm"), w("-rf"), w("/")])),
            vec!["rm", "-rf", "/"]
        );
    }

    #[test]
    fn unwraps_chroot_newroot_and_command() {
        assert_eq!(
            texts(unwrap_transparent_prefix(&[
                w("chroot"),
                w("/mnt/root"),
                w("rm"),
                w("-rf"),
                w("/")
            ])),
            vec!["rm", "-rf", "/"]
        );
        // Attached long option before NEWROOT.
        assert_eq!(
            texts(unwrap_transparent_prefix(&[
                w("chroot"),
                w("--userspec=root:root"),
                w("/mnt"),
                w("rm"),
                w("-rf"),
                w("/etc")
            ])),
            vec!["rm", "-rf", "/etc"]
        );
    }

    #[test]
    fn chroot_benign_and_no_command() {
        assert_eq!(
            texts(unwrap_transparent_prefix(&[w("chroot"), w("/mnt/root"), w("ls")])),
            vec!["ls"]
        );
        // NEWROOT only, no command -> nothing to judge.
        assert!(unwrap_transparent_prefix(&[w("chroot"), w("/mnt")]).is_empty());
    }

    #[test]
    fn unwraps_chroot_separate_value_long_options() {
        // GNU `--userspec VALUE` / `--groups VALUE` in separate-token form.
        assert_eq!(
            texts(unwrap_transparent_prefix(&[
                w("chroot"),
                w("--userspec"),
                w("root:root"),
                w("/mnt"),
                w("rm"),
                w("-rf"),
                w("/")
            ])),
            vec!["rm", "-rf", "/"]
        );
        assert_eq!(
            texts(unwrap_transparent_prefix(&[
                w("chroot"),
                w("--groups"),
                w("wheel"),
                w("/mnt"),
                w("rm"),
                w("-rf"),
                w("/")
            ])),
            vec!["rm", "-rf", "/"]
        );
    }

    #[test]
    fn unwraps_chroot_bsd_short_value_options() {
        // BSD/macOS chroot short value options: -u, -g, -G, -U.
        for flag in ["-u", "-g", "-G", "-U"] {
            let seg = vec![
                w("chroot"),
                w(flag),
                w("root"),
                w("/mnt"),
                w("rm"),
                w("-rf"),
                w("/"),
            ];
            assert_eq!(
                texts(unwrap_transparent_prefix(&seg)),
                vec!["rm", "-rf", "/"],
                "flag {flag}"
            );
        }
    }

    #[test]
    fn chroot_separate_value_options_benign_still_allow_shaped() {
        assert_eq!(
            texts(unwrap_transparent_prefix(&[
                w("chroot"),
                w("--userspec"),
                w("root:root"),
                w("/mnt"),
                w("ls")
            ])),
            vec!["ls"]
        );
        assert_eq!(
            texts(unwrap_transparent_prefix(&[
                w("chroot"),
                w("-u"),
                w("root"),
                w("/mnt"),
                w("ls")
            ])),
            vec!["ls"]
        );
    }

    #[test]
    fn unwraps_flock_lockfile_and_command() {
        assert_eq!(
            texts(unwrap_transparent_prefix(&[
                w("flock"),
                w("/tmp/lock"),
                w("rm"),
                w("-rf"),
                w("/")
            ])),
            vec!["rm", "-rf", "/"]
        );
        // value-taking -w with a boolean -n mixed in
        assert_eq!(
            texts(unwrap_transparent_prefix(&[
                w("flock"),
                w("-w"),
                w("5"),
                w("/tmp/lock"),
                w("rm"),
                w("-rf"),
                w("/")
            ])),
            vec!["rm", "-rf", "/"]
        );
        assert_eq!(
            texts(unwrap_transparent_prefix(&[
                w("flock"),
                w("-n"),
                w("/var/lock/x"),
                w("rm"),
                w("-rf"),
                w("~")
            ])),
            vec!["rm", "-rf", "~"]
        );
    }

    #[test]
    fn flock_benign_and_fd_only() {
        assert_eq!(
            texts(unwrap_transparent_prefix(&[w("flock"), w("/tmp/lock"), w("ls")])),
            vec!["ls"]
        );
        assert_eq!(
            texts(unwrap_transparent_prefix(&[
                w("flock"),
                w("/tmp/lock"),
                w("echo"),
                w("hi")
            ])),
            vec!["echo", "hi"]
        );
        // `flock -n 9` — fd form, no command after the positional.
        assert!(unwrap_transparent_prefix(&[w("flock"), w("-n"), w("9")]).is_empty());
    }

    #[test]
    fn unwraps_bare_command() {
        let seg = vec![w("command"), w("rm"), w("-rf"), w("/")];
        assert_eq!(texts(unwrap_transparent_prefix(&seg)), vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn unwraps_bare_env() {
        let seg = vec![w("env"), w("rm"), w("-rf"), w("/")];
        assert_eq!(texts(unwrap_transparent_prefix(&seg)), vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn unwraps_env_with_leading_assignments() {
        let seg = vec![
            w("env"),
            w("FOO=bar"),
            w("BAZ=1"),
            w("rm"),
            w("-rf"),
            w("/"),
        ];
        assert_eq!(texts(unwrap_transparent_prefix(&seg)), vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn unwraps_nohup_nice_stdbuf_ionice() {
        for prog in ["nohup", "nice", "stdbuf", "ionice"] {
            let seg = vec![w(prog), w("rm"), w("-rf"), w("/")];
            assert_eq!(
                texts(unwrap_transparent_prefix(&seg)),
                vec!["rm", "-rf", "/"],
                "prefix {prog}"
            );
        }
    }

    #[test]
    fn unwraps_nice_with_n_flag() {
        let seg = vec![w("nice"), w("-n"), w("10"), w("rm"), w("-rf"), w("/")];
        assert_eq!(texts(unwrap_transparent_prefix(&seg)), vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn unwraps_nice_with_short_numeric_flag() {
        let seg = vec![w("nice"), w("-10"), w("rm"), w("-rf"), w("/")];
        assert_eq!(texts(unwrap_transparent_prefix(&seg)), vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn unwraps_stacked_wrappers() {
        let seg = vec![w("nohup"), w("env"), w("nice"), w("rm"), w("-rf"), w("/")];
        assert_eq!(texts(unwrap_transparent_prefix(&seg)), vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn unwraps_bare_sudo() {
        let seg = vec![w("sudo"), w("rm"), w("-rf"), w("/")];
        assert_eq!(texts(unwrap_transparent_prefix(&seg)), vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn unwraps_sudo_with_boolean_flags() {
        for flag in ["-n", "-E", "-i", "-H", "-s", "-b", "-k", "-K", "-v", "-l", "-A", "-S"] {
            let seg = vec![w("sudo"), w(flag), w("rm"), w("-rf"), w("/")];
            assert_eq!(
                texts(unwrap_transparent_prefix(&seg)),
                vec!["rm", "-rf", "/"],
                "flag {flag}"
            );
        }
    }

    #[test]
    fn unwraps_sudo_with_short_arg_taking_flag_separate_value() {
        let seg = vec![w("sudo"), w("-u"), w("root"), w("rm"), w("-rf"), w("/")];
        assert_eq!(texts(unwrap_transparent_prefix(&seg)), vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn unwraps_sudo_with_short_arg_taking_flag_attached_value() {
        let seg = vec![w("sudo"), w("-uroot"), w("rm"), w("-rf"), w("/")];
        assert_eq!(texts(unwrap_transparent_prefix(&seg)), vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn unwraps_sudo_with_long_arg_taking_flag_separate_value() {
        let seg = vec![w("sudo"), w("--user"), w("root"), w("rm"), w("-rf"), w("/")];
        assert_eq!(texts(unwrap_transparent_prefix(&seg)), vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn unwraps_sudo_with_long_arg_taking_flag_equals_value() {
        let seg = vec![w("sudo"), w("--user=root"), w("rm"), w("-rf"), w("/")];
        assert_eq!(texts(unwrap_transparent_prefix(&seg)), vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn unwraps_sudo_with_leading_var_assignment() {
        let seg = vec![w("sudo"), w("FOO=bar"), w("rm"), w("-rf"), w("/")];
        assert_eq!(texts(unwrap_transparent_prefix(&seg)), vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn unwraps_sudo_multiple_flags_composed() {
        let seg = vec![
            w("sudo"),
            w("-n"),
            w("-u"),
            w("root"),
            w("gcloud"),
            w("projects"),
            w("delete"),
            w("p"),
        ];
        assert_eq!(
            texts(unwrap_transparent_prefix(&seg)),
            vec!["gcloud", "projects", "delete", "p"]
        );
    }

    #[test]
    fn lone_sudo_unwraps_to_empty() {
        let seg = vec![w("sudo")];
        assert!(unwrap_transparent_prefix(&seg).is_empty());
    }

    #[test]
    fn sudo_help_unwraps_to_empty() {
        let seg = vec![w("sudo"), w("--help")];
        assert!(unwrap_transparent_prefix(&seg).is_empty());
    }

    #[test]
    fn sudo_composes_with_other_wrappers() {
        let seg = vec![w("nohup"), w("sudo"), w("-u"), w("root"), w("rm"), w("-rf"), w("/")];
        assert_eq!(texts(unwrap_transparent_prefix(&seg)), vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn unwraps_case_insensitively() {
        let seg = vec![w("COMMAND"), w("RM"), w("-rf"), w("/")];
        assert_eq!(texts(unwrap_transparent_prefix(&seg)), vec!["RM", "-rf", "/"]);
    }

    #[test]
    fn non_wrapper_is_unchanged() {
        let seg = vec![w("git"), w("status")];
        assert_eq!(texts(unwrap_transparent_prefix(&seg)), vec!["git", "status"]);
    }

    #[test]
    fn plain_ls_through_sudo_stays_allow_shaped() {
        assert_eq!(texts(unwrap_transparent_prefix(&[w("sudo"), w("ls")])), vec!["ls"]);
        assert_eq!(
            texts(unwrap_transparent_prefix(&[
                w("sudo"),
                w("-u"),
                w("root"),
                w("ls")
            ])),
            vec!["ls"]
        );
    }

    #[test]
    fn plain_ls_through_command_and_env_stays_allow_shaped() {
        assert_eq!(
            texts(unwrap_transparent_prefix(&[w("command"), w("ls")])),
            vec!["ls"]
        );
        assert_eq!(
            texts(unwrap_transparent_prefix(&[w("env"), w("ls")])),
            vec!["ls"]
        );
    }
}
