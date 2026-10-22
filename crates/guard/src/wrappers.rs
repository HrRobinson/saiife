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
//! Each wrapper's options are read with `crate::getopt` from one table per
//! wrapper (`spec`), copied from the tool's own option list (see the table
//! comments): which options take a value, the long option prefixes getopt
//! accepts (`--adj 5`, `--arg-f FILE`), and short bundles (`-0a FILE`).
//! Peeling, the files a wrapper reads (`wrapper_reads`), `env -S`
//! (`env_split_payloads`) and the unknown-option check all use these
//! tables, so they cannot disagree.
//!
//! Handled here (transparent prefixes, returning a sub-slice of the same
//! segment): `command`, `env` (leading `VAR=val` assignments and options;
//! the `-S` string is judged by the engine as a command line), `nohup`,
//! `setsid`, `nice`, `stdbuf`, `ionice`, `sudo` (assignments and options),
//! `time`, and the positional-skip wrappers `timeout` (options then one
//! duration positional), `chroot` (options then one NEWROOT positional),
//! and `flock` (options then one lockfile positional, prefix form only).
//! Full-path invocations (`/usr/bin/time`) are recognized.
//!
//! Two more wrappers are handled *elsewhere*, not as transparent prefixes:
//! `su -c '…'` and `watch …` route through `crate::payload` and the engine's
//! inline-payload recursion, because the wrapped command is a string the
//! shell re-parses rather than a leading sub-slice (and `su`'s first operand
//! is a username, which a blind prefix-skip would misread).
//!
//! `exec`, `builtin` and `xargs` are peeled too (xargs: the command and its
//! fixed operands are judged; operands arriving on stdin stay invisible; an
//! `-a FILE` it reads is reported by `wrapper_reads`). `eval` is handled by
//! the engine (its joined arguments are a nested command line).
//!
//! Deliberately not exhaustive. A documented gap remains: the
//! `flock … -c 'STRING'` sub-form (see the design doc's "Known
//! limitations").

use crate::getopt::{flag, opt, req, Opt, Spec};
use crate::lexer::Word;

/// Command names that transparently wrap another command. Matched
/// case-insensitively against each word's text, mirroring the case-fold
/// applied to argv[0] elsewhere in the pipeline (macOS's case-insensitive
/// filesystem means `COMMAND rm -rf /` finds the same binary as `command`).
const TRANSPARENT_PREFIXES: &[&str] = &[
    "command", "env", "nohup", "nice", "stdbuf", "ionice", "sudo", "time", "timeout", "chroot",
    "flock", "exec", "xargs", "builtin", "setsid",
];

// ---- Option tables -----------------------------------------------------------
//
// Each table is the tool's option list as installed on the reference
// machine (Arch Linux, 2026-10): `--help` of the tool, with every option's
// arity checked by running it bare (`tool -x`: "requires an argument") and
// long ones also as `--name` / `--name=x`. Options of the BSD/macOS
// variants are added where they take a value, so a macOS host peels them
// too (GNU refuses them, so nothing is hidden on Linux). `pin_*` tests in
// this file pin every table.

/// GNU coreutils 9.11 `env` (`+a:C:iS:u:v0`); BSD `-P altpath`.
pub(crate) const ENV: Spec<'static> = Spec::new(
    "+0a:C:iP:S:u:v",
    &[
        req("argv0", 'a'),
        flag("ignore-environment", 'i'),
        flag("null", '0'),
        req("unset", 'u'),
        req("chdir", 'C'),
        req("split-string", 'S'),
        opt("block-signal", '\0'),
        opt("default-signal", '\0'),
        opt("ignore-signal", '\0'),
        flag("list-signal-handling", '\0'),
        flag("debug", 'v'),
        flag("help", '\0'),
        flag("version", '\0'),
    ],
);

/// GNU coreutils 9.11 `nice` (`-n N`; the obsolete `-N` is one word).
const NICE: Spec<'static> = Spec::new(
    "+n:",
    &[
        req("adjustment", 'n'),
        flag("help", '\0'),
        flag("version", '\0'),
    ],
);

/// util-linux 2.42.3 `ionice` (`+c:hn:p:P:tu:V`).
const IONICE: Spec<'static> = Spec::new(
    "+c:hn:p:P:tu:V",
    &[
        req("class", 'c'),
        req("classdata", 'n'),
        req("pid", 'p'),
        req("pgid", 'P'),
        flag("ignore", 't'),
        req("uid", 'u'),
        flag("help", 'h'),
        flag("version", 'V'),
    ],
);

/// GNU coreutils 9.11 `stdbuf`.
const STDBUF: Spec<'static> = Spec::new(
    "+i:o:e:",
    &[
        req("input", 'i'),
        req("output", 'o'),
        req("error", 'e'),
        flag("help", '\0'),
        flag("version", '\0'),
    ],
);

/// util-linux 2.42.3 `setsid`.
const SETSID: Spec<'static> = Spec::new(
    "+cfwhV",
    &[
        flag("ctty", 'c'),
        flag("fork", 'f'),
        flag("wait", 'w'),
        flag("help", 'h'),
        flag("version", 'V'),
    ],
);

/// GNU coreutils 9.11 `nohup`: no options but `--help`/`--version` (and
/// `--`, which ends them: `nohup -- rm -rf /` runs `rm`).
const NOHUP: Spec<'static> = Spec::new("+", &[flag("help", '\0'), flag("version", '\0')]);

/// GNU coreutils 9.11 `timeout`.
const TIMEOUT: Spec<'static> = Spec::new(
    "+fk:ps:v",
    &[
        flag("foreground", 'f'),
        req("kill-after", 'k'),
        flag("preserve-status", 'p'),
        req("signal", 's'),
        flag("verbose", 'v'),
        flag("help", '\0'),
        flag("version", '\0'),
    ],
);

/// GNU time 1.9 (`/usr/bin/time`; not installed on the reference machine,
/// taken from its documented option list); bash's `time -p` is a subset.
const TIME: Spec<'static> = Spec::new(
    "+af:o:pqvV",
    &[
        flag("append", 'a'),
        req("format", 'f'),
        req("output", 'o'),
        flag("portability", 'p'),
        flag("quiet", 'q'),
        flag("verbose", 'v'),
        flag("help", '\0'),
        flag("version", 'V'),
    ],
);

/// GNU coreutils 9.11 `chroot` (long options only); BSD/macOS `-u user`,
/// `-g group`, `-G list`, `-U user`.
const CHROOT: Spec<'static> = Spec::new(
    "+u:g:G:U:",
    &[
        req("groups", '\0'),
        req("userspec", '\0'),
        flag("skip-chdir", '\0'),
        flag("help", '\0'),
        flag("version", '\0'),
    ],
);

/// util-linux 2.42.3 `flock` (`+sexnoFuw:E:hV`; `-c` is only accepted
/// after the lock file, and there is no `--command`). `--wait` is
/// `--timeout`; `--nb` is `--nonblocking`.
const FLOCK: Spec<'static> = Spec::new(
    "+sexnoFuw:E:hV",
    &[
        flag("shared", 's'),
        flag("exclusive", 'x'),
        flag("unlock", 'u'),
        flag("nonblocking", 'n'),
        flag("nb", 'n'),
        req("timeout", 'w'),
        req("wait", 'w'),
        req("conflict-exit-code", 'E'),
        flag("close", 'o'),
        flag("no-fork", 'F'),
        flag("fcntl", '\0'),
        req("start", '\0'),
        req("length", '\0'),
        flag("verbose", '\0'),
        flag("help", 'h'),
        flag("version", 'V'),
    ],
);

/// bash's `exec [-cl] [-a name]`.
const EXEC: Spec<'static> = Spec::new("cla:", &[]);

/// GNU findutils 4.11.0 `xargs` (`+0a:E:e::i::I:l::L:n:prs:txP:d:o`;
/// `--eof`, `--replace` and `--max-lines` take their value attached only);
/// BSD/macOS `-J replstr`, `-R replacements`, `-S replsize`.
pub(crate) const XARGS: Spec<'static> = Spec::new(
    "+0a:E:e::i::I:l::L:n:prs:txP:d:oJ:R:S:",
    &[
        flag("null", '0'),
        req("arg-file", 'a'),
        req("delimiter", 'd'),
        opt("eof", 'e'),
        opt("replace", 'I'),
        opt("max-lines", 'l'),
        req("max-args", 'n'),
        req("max-procs", 'P'),
        req("max-chars", 's'),
        flag("interactive", 'p'),
        flag("verbose", 't'),
        flag("no-run-if-empty", 'r'),
        flag("exit", 'x'),
        flag("open-tty", 'o'),
        flag("show-limits", '\0'),
        req("process-slot-var", '\0'),
        flag("help", '\0'),
        flag("version", '\0'),
    ],
);

/// sudo 1.9.17p2 (`--help`; optstring `+Aa:BbC:c:D:Eeg:Hh::iKklNnPp:R:r:
/// SsT:t:U:u:Vv` from the binary). `-h` takes its host only attached in
/// getopt terms, but sudo also takes a following non-option word as the
/// host (`sudo -h host cmd`), so it is read as value-taking here.
pub(crate) const SUDO: Spec<'static> = Spec::new(
    "+Aa:BbC:c:D:Eeg:Hh:iKklNnPp:R:r:SsT:t:U:u:Vv",
    &[
        flag("askpass", 'A'),
        req("auth-type", 'a'),
        flag("background", 'b'),
        flag("bell", 'B'),
        req("close-from", 'C'),
        req("login-class", 'c'),
        req("chdir", 'D'),
        opt("preserve-env", 'E'),
        flag("edit", 'e'),
        req("group", 'g'),
        flag("set-home", 'H'),
        flag("help", 'h'),
        req("host", '\0'),
        flag("login", 'i'),
        flag("remove-timestamp", 'K'),
        flag("reset-timestamp", 'k'),
        flag("list", 'l'),
        flag("non-interactive", 'n'),
        flag("no-update", 'N'),
        flag("preserve-groups", 'P'),
        req("prompt", 'p'),
        req("chroot", 'R'),
        req("role", 'r'),
        flag("stdin", 'S'),
        flag("shell", 's'),
        req("type", 't'),
        req("command-timeout", 'T'),
        req("other-user", 'U'),
        req("user", 'u'),
        flag("version", 'V'),
        flag("validate", 'v'),
    ],
);

/// The option table of a peeled wrapper; `None` for `command` (`-p`, `-v`,
/// `-V`, all flags: every leading `-` word is skipped) and `builtin`.
pub(crate) fn spec(wrapper: &str) -> Option<&'static Spec<'static>> {
    Some(match wrapper {
        "env" => &ENV,
        "nice" => &NICE,
        "ionice" => &IONICE,
        "stdbuf" => &STDBUF,
        "setsid" => &SETSID,
        "nohup" => &NOHUP,
        "timeout" => &TIMEOUT,
        "time" => &TIME,
        "chroot" => &CHROOT,
        "flock" => &FLOCK,
        "exec" => &EXEC,
        "xargs" => &XARGS,
        "sudo" => &SUDO,
        _ => return None,
    })
}

/// Peel any number of transparent wrapper commands off the front of a
/// segment's words, returning the slice starting at the effective command.
/// Each iteration of the outer loop consumes at least the wrapper's own
/// name, so this is bounded by the segment's length and cannot loop
/// unboundedly on adversarial input (no risk to the latency budget).
pub fn unwrap_transparent_prefix(seg: &[Word]) -> &[Word] {
    let mut rest = seg;
    while let Some((_, after)) = unwrap_one(rest) {
        rest = after;
    }
    rest
}

/// Peel one transparent wrapper off the front of `rest`: its (lowered,
/// directory-stripped) name and the words after it and its options.
fn unwrap_one(rest: &[Word]) -> Option<(String, &[Word])> {
    let head = rest.first()?;
    // Strip any leading directory (`/usr/bin/time` -> `time`) and
    // case-fold before matching — the same canonicalization
    // `normalize::build_argv` applies to argv[0], but done here because
    // unwrapping runs on the raw segment *before* that normalization.
    // Skip-only, so this can only ever catch more, never manufacture a
    // false positive.
    let lowered = head.text.to_ascii_lowercase();
    let name = strip_program_dir(&lowered);
    if !TRANSPARENT_PREFIXES.contains(&name) {
        return None;
    }
    let mut rest = &rest[1..];
    match name {
        // `env [OPTION]... [-] [NAME=VALUE]... CMD`: options, `-` (= `-i`)
        // and assignments, in any order.
        "env" => rest = skip_options(&ENV, rest, true, true),
        // `sudo [OPTION]... [VAR=value]... CMD`.
        "sudo" => rest = skip_options(&SUDO, rest, true, false),
        "command" => {
            while rest
                .first()
                .map(|w| w.text.starts_with('-'))
                .unwrap_or(false)
            {
                rest = &rest[1..];
            }
        }
        "builtin" => {}
        // `timeout [OPTION]... DURATION CMD`: one DURATION positional,
        // gated by a duration shape so a malformed `timeout rm …` never
        // eats a command.
        "timeout" => {
            rest = skip_options_then_positionals(rest, &TIMEOUT, 1, Some(is_duration_shape))
        }
        // `chroot [OPTION]... NEWROOT [CMD]` (a recursive wipe of the
        // chroot's own root is still the catastrophe class we block — see
        // the design's DECISION 5).
        "chroot" => rest = skip_options_then_positionals(rest, &CHROOT, 1, None),
        // `flock [OPTION]... LOCKFILE CMD`. The `flock … -c 'STRING'`
        // sub-form is deferred (design DECISION 4): it puts an inline
        // payload after the positional and is a documented gap.
        "flock" => rest = skip_options_then_positionals(rest, &FLOCK, 1, None),
        // nice, ionice, stdbuf, setsid, nohup, time, exec, xargs: options,
        // then the command. xargs' operands arrive on stdin, but the
        // command and its fixed operands are visible.
        other => {
            if let Some(spec) = spec(other) {
                rest = skip_options_then_positionals(rest, spec, 0, None);
            }
        }
    }
    Some((name.to_string(), rest))
}

/// The options of a wrapper peeled off a segment: `args` are the words
/// after its name, of which the first `opts` are its own (options, their
/// values, assignments, positionals). Tells `visit` about each option.
fn wrapper_options<'w>(
    spec: &'static Spec<'static>,
    args: &'w [Word],
    opts: usize,
    visit: &mut dyn FnMut(Opt<'static, 'w>, &'w [Word]),
) {
    let args = &args[..opts.min(args.len())];
    let mut i = 0;
    while i < args.len() {
        match spec.option_at(args, i, &mut |o| visit(o, args)) {
            Some(next) => i = next,
            None => i += 1,
        }
    }
}

/// Files the wrappers peeled off in front of a segment's command read
/// themselves: `xargs -a FILE` / `--arg-file FILE` (also attached, bundled
/// and abbreviated: `-0a FILE`, `-aFILE`, `--arg-file=FILE`, `--arg FILE`).
/// Follows the same peeling as `effective_command`.
pub fn wrapper_reads(seg: &[Word]) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    peel(seg, &mut |name, args, opts| {
        if name != "xargs" {
            return;
        }
        wrapper_options(&XARGS, args, opts, &mut |o, args| {
            if let Opt::Known {
                short: 'a',
                value: Some(file),
                word,
                separate,
                ..
            } = o
            {
                let glob = args
                    .get(if separate { word + 1 } else { word })
                    .is_some_and(|w| w.glob);
                out.push((file.to_string(), glob));
            }
        });
    });
    out
}

/// The command a segment runs: transparent wrappers (`sudo`, `env`, …),
/// leading `NAME=value` assignments (`LANG=C sort f`) and leading
/// redirections with their targets (`2>/dev/null cat f`) peeled off, in
/// any order and any number. The redirections stay in the segment, where
/// `operands` judges them; whole-segment rules still see the assignments.
pub fn effective_command(seg: &[Word]) -> &[Word] {
    peel(seg, &mut |_, _, _| {})
}

/// The names of the wrappers `effective_command` peels off, in order
/// (lowered, directory stripped): `timeout 5 xargs sudo ls` gives
/// `["timeout", "xargs", "sudo"]`.
pub fn peeled_wrappers(seg: &[Word]) -> Vec<String> {
    let mut names = Vec::new();
    peel(seg, &mut |name, _, _| names.push(name.to_string()));
    names
}

/// One `env -S STRING`: the string as given, and the command line it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvSplit {
    pub string: String,
    pub line: String,
}

/// The command lines hidden in `env -S STRING` (`--split-string[=]STRING`,
/// `-SSTRING`, `-iS STRING`, `--sp=…`) of every `env` peeled off the
/// segment: `env`, the string, and the words after it, joined with spaces,
/// to be judged as a command line of its own (env splits the string into
/// arguments and runs them with the rest appended).
pub fn env_split_payloads(seg: &[Word]) -> Vec<EnvSplit> {
    let mut out = Vec::new();
    // Cheap pre-check: no option word that could be `-S`/`--split-string`.
    if !seg
        .iter()
        .any(|w| w.text.starts_with('-') && w.text.contains(['S', 's']))
    {
        return out;
    }
    peel(seg, &mut |name, args, opts| {
        if name != "env" {
            return;
        }
        let mut found: Option<(String, usize)> = None;
        wrapper_options(&ENV, args, opts, &mut |o, _| {
            if let Opt::Known {
                short: 'S',
                value: Some(v),
                word,
                separate,
                ..
            } = o
            {
                if found.is_none() {
                    found = Some((v.to_string(), word + if separate { 2 } else { 1 }));
                }
            }
        });
        if let Some((payload, next)) = found {
            let tail = args[next.min(args.len())..]
                .iter()
                .map(|w| w.text.as_str())
                .collect::<Vec<_>>();
            let mut line = format!("env {payload}");
            if !tail.is_empty() {
                line.push(' ');
                line.push_str(&tail.join(" "));
            }
            out.push(EnvSplit {
                string: payload,
                line,
            });
        }
    });
    out
}

/// Long options (`--name`, `--name=value`) of the wrappers peeled off the
/// segment that are not one of the wrapper's options, nor an unambiguous
/// prefix of one. The wrapper itself would refuse them, but a newer version
/// may know an option that takes a value, which would make saiife judge
/// the wrong word as the command: the caller records the segment as not
/// fully judged.
pub fn unknown_wrapper_options(seg: &[Word]) -> Vec<String> {
    let mut out = Vec::new();
    if !seg.iter().any(|w| w.text.starts_with("--")) {
        return out;
    }
    peel(seg, &mut |name, args, opts| {
        // Shell builtins (`exec`) have no long options to check.
        let Some(spec) = spec(name).filter(|s| !s.long.is_empty()) else {
            return;
        };
        wrapper_options(spec, args, opts, &mut |o, _| {
            if let Opt::Unknown { name: opt } = o {
                out.push(format!("{name} --{opt}"));
            }
        });
    });
    out
}

/// What `peel` tells its visitor about each wrapper: its name, the words
/// after the name, and how many of them are the wrapper's own options.
type Visit<'v, 'a> = &'v mut dyn FnMut(&str, &'a [Word], usize);

/// Peel wrappers off the front of `rest`, telling `visit` about each.
fn unwrap_visit<'a>(mut rest: &'a [Word], visit: Visit<'_, 'a>) -> &'a [Word] {
    while let Some((name, after)) = unwrap_one(rest) {
        let args = &rest[1..];
        visit(&name, args, args.len() - after.len());
        rest = after;
    }
    rest
}

fn peel<'a>(seg: &'a [Word], visit: Visit<'_, 'a>) -> &'a [Word] {
    let mut rest = unwrap_visit(seg, visit);
    loop {
        let before = rest.len();
        while let Some(w) = rest.first() {
            if w.redirect {
                rest = &rest[rest.len().min(2)..];
            } else if w.assignment {
                rest = &rest[1..];
            } else {
                break;
            }
        }
        rest = unwrap_visit(rest, visit);
        if rest.len() == before {
            return rest;
        }
    }
}

/// Skip a wrapper's options (with their values), and its `NAME=value`
/// assignments when `assignments` (env, sudo), to reach the command. `--`
/// ends the options; a lone `-` is an option when `lone_dash` (env's `-`
/// is `-i`), else the command. Bounded: every step consumes a word.
fn skip_options<'a>(
    spec: &Spec<'_>,
    rest: &'a [Word],
    assignments: bool,
    lone_dash: bool,
) -> &'a [Word] {
    let mut i = 0;
    while let Some(w) = rest.get(i) {
        let t = w.text.as_str();
        if assignments && is_env_assignment(t) || lone_dash && t == "-" {
            i += 1;
            continue;
        }
        match spec.option_at(rest, i, &mut |_| {}) {
            Some(next) => i = next,
            None if t == "--" => {
                i += 1;
                break;
            }
            None => break,
        }
    }
    &rest[i.min(rest.len())..]
}

/// Skip a wrapper's leading options and then up to `positionals` operand
/// tokens, returning the slice starting at the effective wrapped command.
///
/// The option phase follows getopt with the wrapper's table (`spec`): a
/// value-taking option takes the next word unless its value is attached
/// (`-w5`, `--timeout=5`); long options may be abbreviated. A bare `--`
/// ends the option phase; a bare `-` is the start of the operands. The
/// positional phase then consumes up to `positionals` non-option tokens,
/// each gated by the optional `positional_shape` predicate — if a slot's
/// token fails the predicate it is *not* skipped and the phase stops (used
/// for `timeout`'s duration-shape guard).
///
/// Bounded by `rest`'s length: every branch consumes at least one token.
fn skip_options_then_positionals<'a>(
    rest: &'a [Word],
    spec: &Spec<'_>,
    positionals: usize,
    positional_shape: Option<fn(&str) -> bool>,
) -> &'a [Word] {
    let mut rest = skip_options(spec, rest, false, false);
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
pub(crate) fn is_env_assignment(tok: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::getopt::req;

    const NONE: Spec<'static> = Spec::new("", &[]);
    const W: Spec<'static> = Spec::new("w:", &[]);
    const LONG_TIMEOUT: Spec<'static> = Spec::new("", &[req("timeout", '\0')]);

    fn w(text: &str) -> Word {
        Word {
            text: text.to_string(),
            has_substitution: false,
            ..Default::default()
        }
    }

    fn texts(seg: &[Word]) -> Vec<&str> {
        seg.iter().map(|w| w.text.as_str()).collect()
    }

    #[test]
    fn helper_skips_boolean_options_only() {
        let seg = vec![w("-x"), w("-n"), w("rm"), w("-rf"), w("/")];
        assert_eq!(
            texts(skip_options_then_positionals(&seg, &NONE, 0, None)),
            vec!["rm", "-rf", "/"]
        );
    }

    #[test]
    fn helper_skips_value_taking_short_separate() {
        let seg = vec![w("-w"), w("5"), w("cmd")];
        assert_eq!(
            texts(skip_options_then_positionals(&seg, &W, 0, None)),
            vec!["cmd"]
        );
    }

    #[test]
    fn helper_attached_short_value_is_one_token() {
        let seg = vec![w("-w5"), w("cmd")];
        assert_eq!(
            texts(skip_options_then_positionals(&seg, &W, 0, None)),
            vec!["cmd"]
        );
    }

    #[test]
    fn helper_skips_value_taking_long_separate_and_attached() {
        let sep = vec![w("--timeout"), w("5"), w("cmd")];
        assert_eq!(
            texts(skip_options_then_positionals(&sep, &LONG_TIMEOUT, 0, None)),
            vec!["cmd"]
        );
        let att = vec![w("--timeout=5"), w("cmd")];
        assert_eq!(
            texts(skip_options_then_positionals(&att, &LONG_TIMEOUT, 0, None)),
            vec!["cmd"]
        );
    }

    #[test]
    fn helper_double_dash_ends_options() {
        let seg = vec![w("-x"), w("--"), w("cmd"), w("-rf")];
        assert_eq!(
            texts(skip_options_then_positionals(&seg, &NONE, 0, None)),
            vec!["cmd", "-rf"]
        );
    }

    #[test]
    fn helper_skips_one_positional() {
        let seg = vec![w("-x"), w("/tmp/lock"), w("rm"), w("-rf"), w("/")];
        assert_eq!(
            texts(skip_options_then_positionals(&seg, &NONE, 1, None)),
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
                &NONE,
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
                &NONE,
                1,
                Some(is_duration_shape)
            )),
            vec!["rm", "-rf", "/"]
        );
    }

    #[test]
    fn helper_no_command_after_options_yields_empty() {
        let seg = vec![w("-x"), w("-n")];
        assert!(skip_options_then_positionals(&seg, &NONE, 0, None).is_empty());
    }

    #[test]
    fn unwraps_time_bare_and_portability_flag() {
        assert_eq!(
            texts(unwrap_transparent_prefix(&[
                w("time"),
                w("rm"),
                w("-rf"),
                w("/")
            ])),
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
            texts(unwrap_transparent_prefix(&[
                w("time"),
                w("-v"),
                w("rm"),
                w("-rf"),
                w("/")
            ])),
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
            texts(unwrap_transparent_prefix(&[
                w("/usr/bin/sudo"),
                w("rm"),
                w("-rf"),
                w("/")
            ])),
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
            texts(unwrap_transparent_prefix(&[
                w("timeout"),
                w("5s"),
                w("rm"),
                w("-rf"),
                w("/")
            ])),
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
        assert!(
            unwrap_transparent_prefix(&[w("timeout")]).is_empty()
                || texts(unwrap_transparent_prefix(&[w("timeout")])) == vec!["timeout"]
        );
        assert!(unwrap_transparent_prefix(&[w("timeout"), w("300")]).is_empty());
    }

    #[test]
    fn timeout_non_duration_positional_is_not_skipped() {
        // Malformed `timeout rm -rf /` — `rm` is not duration-shaped, so the
        // duration slot is not consumed; `rm` stays at argv[0] (still caught
        // as a real command by the pack, but proves the shape guard works).
        assert_eq!(
            texts(unwrap_transparent_prefix(&[
                w("timeout"),
                w("rm"),
                w("-rf"),
                w("/")
            ])),
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
            texts(unwrap_transparent_prefix(&[
                w("chroot"),
                w("/mnt/root"),
                w("ls")
            ])),
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
            texts(unwrap_transparent_prefix(&[
                w("flock"),
                w("/tmp/lock"),
                w("ls")
            ])),
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
        assert_eq!(
            texts(unwrap_transparent_prefix(&seg)),
            vec!["rm", "-rf", "/"]
        );
    }

    #[test]
    fn unwraps_bare_env() {
        let seg = vec![w("env"), w("rm"), w("-rf"), w("/")];
        assert_eq!(
            texts(unwrap_transparent_prefix(&seg)),
            vec!["rm", "-rf", "/"]
        );
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
        assert_eq!(
            texts(unwrap_transparent_prefix(&seg)),
            vec!["rm", "-rf", "/"]
        );
    }

    /// `-u NAME`, `-C DIR`, `-a ARG0`, `-P PATH` and their long forms take
    /// the next word; attached and `=` forms are one word.
    #[test]
    fn unwraps_env_value_options() {
        let line = |s: &str| {
            let seg: Vec<Word> = s.split(' ').map(w).collect();
            texts(unwrap_transparent_prefix(&seg)).join(" ")
        };
        for s in [
            "env -u FOO rm -rf /",
            "env -iu FOO rm -rf /",
            "env --unset FOO rm -rf /",
            "env --unset=FOO rm -rf /",
            "env -uFOO rm -rf /",
            "env -C /tmp rm -rf /",
            "env --chdir /tmp X=1 rm -rf /",
            "env -P /bin rm -rf /",
            "env -a x rm -rf /",
            "env -i rm -rf /",
        ] {
            assert_eq!(line(s), "rm -rf /", "{s}");
        }
        assert_eq!(line("env -u FOO"), "");
    }

    #[test]
    fn env_split_string_payloads() {
        let p = |words: &[&str]| {
            let seg: Vec<Word> = words.iter().map(|s| w(s)).collect();
            env_split_payloads(&seg)
                .into_iter()
                .map(|e| e.line)
                .collect::<Vec<_>>()
        };
        assert_eq!(p(&["env", "-S", "sudo ls"]), ["env sudo ls"]);
        assert_eq!(p(&["env", "--sp=a b"]), ["env a b"]);
        assert_eq!(p(&["env", "--split-s", "a b"]), ["env a b"]);
        assert_eq!(p(&["env", "--un", "S", "ls"]), Vec::<String>::new());
        let seg: Vec<Word> = ["env", "-S", "a\\_b", "c#"].iter().map(|s| w(s)).collect();
        assert_eq!(env_split_payloads(&seg)[0].string, "a\\_b");
        assert_eq!(p(&["env", "-Ssudo ls", "x"]), ["env sudo ls x"]);
        assert_eq!(p(&["env", "-iS", "a b"]), ["env a b"]);
        assert_eq!(p(&["env", "--split-string=a b"]), ["env a b"]);
        assert_eq!(p(&["env", "--split-string", "a b", "c"]), ["env a b c"]);
        assert_eq!(p(&["env", "-u", "S", "ls"]), Vec::<String>::new());
        assert_eq!(p(&["timeout", "5", "env", "-S", "a"]), ["env a"]);
        assert!(p(&["env", "ls", "-S", "x"]).is_empty());
        assert!(p(&["ls", "-S"]).is_empty());
    }

    #[test]
    fn peeled_wrappers_names_every_wrapper_in_order() {
        let names = |s: &str| {
            let seg: Vec<Word> = s.split(' ').map(w).collect();
            peeled_wrappers(&seg)
        };
        assert_eq!(
            names("timeout 5 /usr/bin/xargs SUDO -u root ls"),
            ["timeout", "xargs", "sudo"]
        );
        assert_eq!(names("sudo -l"), ["sudo"]);
        assert!(names("ls -la").is_empty());
        assert!(names("echo sudo").is_empty());
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
        assert_eq!(
            texts(unwrap_transparent_prefix(&seg)),
            vec!["rm", "-rf", "/"]
        );
    }

    #[test]
    fn unwraps_nice_with_short_numeric_flag() {
        let seg = vec![w("nice"), w("-10"), w("rm"), w("-rf"), w("/")];
        assert_eq!(
            texts(unwrap_transparent_prefix(&seg)),
            vec!["rm", "-rf", "/"]
        );
    }

    #[test]
    fn unwraps_stacked_wrappers() {
        let seg = vec![w("nohup"), w("env"), w("nice"), w("rm"), w("-rf"), w("/")];
        assert_eq!(
            texts(unwrap_transparent_prefix(&seg)),
            vec!["rm", "-rf", "/"]
        );
    }

    #[test]
    fn unwraps_bare_sudo() {
        let seg = vec![w("sudo"), w("rm"), w("-rf"), w("/")];
        assert_eq!(
            texts(unwrap_transparent_prefix(&seg)),
            vec!["rm", "-rf", "/"]
        );
    }

    #[test]
    fn unwraps_sudo_with_boolean_flags() {
        for flag in [
            "-n", "-E", "-i", "-H", "-s", "-b", "-k", "-K", "-v", "-l", "-A", "-S",
        ] {
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
        assert_eq!(
            texts(unwrap_transparent_prefix(&seg)),
            vec!["rm", "-rf", "/"]
        );
    }

    #[test]
    fn unwraps_sudo_with_short_arg_taking_flag_attached_value() {
        let seg = vec![w("sudo"), w("-uroot"), w("rm"), w("-rf"), w("/")];
        assert_eq!(
            texts(unwrap_transparent_prefix(&seg)),
            vec!["rm", "-rf", "/"]
        );
    }

    #[test]
    fn unwraps_sudo_with_long_arg_taking_flag_separate_value() {
        let seg = vec![w("sudo"), w("--user"), w("root"), w("rm"), w("-rf"), w("/")];
        assert_eq!(
            texts(unwrap_transparent_prefix(&seg)),
            vec!["rm", "-rf", "/"]
        );
    }

    #[test]
    fn unwraps_sudo_with_long_arg_taking_flag_equals_value() {
        let seg = vec![w("sudo"), w("--user=root"), w("rm"), w("-rf"), w("/")];
        assert_eq!(
            texts(unwrap_transparent_prefix(&seg)),
            vec!["rm", "-rf", "/"]
        );
    }

    #[test]
    fn unwraps_sudo_with_leading_var_assignment() {
        let seg = vec![w("sudo"), w("FOO=bar"), w("rm"), w("-rf"), w("/")];
        assert_eq!(
            texts(unwrap_transparent_prefix(&seg)),
            vec!["rm", "-rf", "/"]
        );
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
        let seg = vec![
            w("nohup"),
            w("sudo"),
            w("-u"),
            w("root"),
            w("rm"),
            w("-rf"),
            w("/"),
        ];
        assert_eq!(
            texts(unwrap_transparent_prefix(&seg)),
            vec!["rm", "-rf", "/"]
        );
    }

    #[test]
    fn unwraps_case_insensitively() {
        let seg = vec![w("COMMAND"), w("RM"), w("-rf"), w("/")];
        assert_eq!(
            texts(unwrap_transparent_prefix(&seg)),
            vec!["RM", "-rf", "/"]
        );
    }

    #[test]
    fn non_wrapper_is_unchanged() {
        let seg = vec![w("git"), w("status")];
        assert_eq!(
            texts(unwrap_transparent_prefix(&seg)),
            vec!["git", "status"]
        );
    }

    #[test]
    fn plain_ls_through_sudo_stays_allow_shaped() {
        assert_eq!(
            texts(unwrap_transparent_prefix(&[w("sudo"), w("ls")])),
            vec!["ls"]
        );
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

    // ---- Option tables, pinned (fix round 4, F3) ---------------------------
    //
    // Each table as the installed tool has it (sources in the table
    // comments). Changing a table means checking the tool again.

    fn render(spec: &Spec<'_>) -> String {
        let long: Vec<String> = spec
            .long
            .iter()
            .map(|o| {
                let arg = match o.arg {
                    crate::getopt::Arg::No => "",
                    crate::getopt::Arg::Required => "=",
                    crate::getopt::Arg::Optional => "[=]",
                };
                let short = if o.short == '\0' {
                    String::new()
                } else {
                    format!("|{}", o.short)
                };
                format!("{}{arg}{short}", o.name)
            })
            .collect();
        format!("{} {}", spec.short, long.join(" "))
    }

    /// Peel `wrapper <opt words> [positional] cmd` and expect `cmd`, for
    /// every option of the table: short (with a value when it takes one),
    /// long in full and as its shortest unambiguous prefix.
    fn peels_every_option(wrapper: &str, positional: Option<&str>) {
        use crate::getopt::{Arg, Resolved};
        let spec = spec(wrapper).unwrap();
        let check = |opt_words: &[&str]| {
            let mut words = vec![wrapper];
            words.extend_from_slice(opt_words);
            words.extend(positional);
            words.extend(["cmd", "-x"]);
            let seg: Vec<Word> = words.iter().map(|s| w(s)).collect();
            assert_eq!(
                texts(unwrap_transparent_prefix(&seg)),
                vec!["cmd", "-x"],
                "{words:?}"
            );
        };
        for c in spec.short.chars().filter(|c| !matches!(c, ':' | '+')) {
            match spec.short_arg(c).unwrap() {
                Arg::Required => {
                    check(&[&format!("-{c}"), "V"]);
                    check(&[&format!("-{c}V")]);
                }
                Arg::Optional => check(&[&format!("-{c}V")]),
                Arg::No => check(&[&format!("-{c}")]),
            }
        }
        for o in spec.long {
            let shortest = (1..=o.name.len())
                .map(|n| &o.name[..n])
                .find(|p| matches!(spec.resolve_long(p), Resolved::Known(k) if k.name == o.name))
                .unwrap_or_else(|| panic!("{wrapper} --{} unreachable", o.name));
            for name in [o.name, shortest] {
                match o.arg {
                    Arg::Required => {
                        check(&[&format!("--{name}"), "V"]);
                        check(&[&format!("--{name}=V")]);
                    }
                    Arg::Optional => check(&[&format!("--{name}=V")]),
                    Arg::No => check(&[&format!("--{name}")]),
                }
            }
        }
    }

    #[test]
    fn pin_env() {
        assert_eq!(
            render(&ENV),
            "+0a:C:iP:S:u:v argv0=|a ignore-environment|i null|0 unset=|u chdir=|C \
             split-string=|S block-signal[=] default-signal[=] ignore-signal[=] \
             list-signal-handling debug|v help version"
        );
        peels_every_option("env", None);
    }

    #[test]
    fn pin_nice() {
        assert_eq!(render(&NICE), "+n: adjustment=|n help version");
        peels_every_option("nice", None);
    }

    #[test]
    fn pin_ionice() {
        assert_eq!(
            render(&IONICE),
            "+c:hn:p:P:tu:V class=|c classdata=|n pid=|p pgid=|P ignore|t uid=|u help|h version|V"
        );
        peels_every_option("ionice", None);
    }

    #[test]
    fn pin_stdbuf() {
        assert_eq!(
            render(&STDBUF),
            "+i:o:e: input=|i output=|o error=|e help version"
        );
        peels_every_option("stdbuf", None);
    }

    #[test]
    fn pin_setsid() {
        assert_eq!(
            render(&SETSID),
            "+cfwhV ctty|c fork|f wait|w help|h version|V"
        );
        peels_every_option("setsid", None);
    }

    #[test]
    fn pin_nohup() {
        assert_eq!(render(&NOHUP), "+ help version");
        peels_every_option("nohup", None);
        let seg: Vec<Word> = ["nohup", "--", "rm", "-rf", "/"].map(w).to_vec();
        assert_eq!(texts(unwrap_transparent_prefix(&seg)), ["rm", "-rf", "/"]);
    }

    #[test]
    fn pin_timeout() {
        assert_eq!(
            render(&TIMEOUT),
            "+fk:ps:v foreground|f kill-after=|k preserve-status|p signal=|s verbose|v help version"
        );
        peels_every_option("timeout", Some("5"));
    }

    #[test]
    fn pin_time() {
        assert_eq!(
            render(&TIME),
            "+af:o:pqvV append|a format=|f output=|o portability|p quiet|q verbose|v help version|V"
        );
        peels_every_option("time", None);
    }

    #[test]
    fn pin_chroot() {
        assert_eq!(
            render(&CHROOT),
            "+u:g:G:U: groups= userspec= skip-chdir help version"
        );
        peels_every_option("chroot", Some("/r"));
    }

    #[test]
    fn pin_flock() {
        assert_eq!(
            render(&FLOCK),
            "+sexnoFuw:E:hV shared|s exclusive|x unlock|u nonblocking|n nb|n timeout=|w \
             wait=|w conflict-exit-code=|E close|o no-fork|F fcntl start= length= verbose \
             help|h version|V"
        );
        peels_every_option("flock", Some("/tmp/l"));
    }

    #[test]
    fn pin_exec() {
        assert_eq!(render(&EXEC), "cla: ");
        peels_every_option("exec", None);
    }

    #[test]
    fn pin_xargs() {
        assert_eq!(
            render(&XARGS),
            "+0a:E:e::i::I:l::L:n:prs:txP:d:oJ:R:S: null|0 arg-file=|a delimiter=|d \
             eof[=]|e replace[=]|I max-lines[=]|l max-args=|n max-procs=|P max-chars=|s \
             interactive|p verbose|t no-run-if-empty|r exit|x open-tty|o show-limits \
             process-slot-var= help version"
        );
        peels_every_option("xargs", None);
        // Optional values are attached only: the next word is the command.
        let seg: Vec<Word> = ["xargs", "--max-lines", "1", "rm"].map(w).to_vec();
        assert_eq!(texts(unwrap_transparent_prefix(&seg)), ["1", "rm"]);
    }

    #[test]
    fn pin_sudo() {
        assert_eq!(
            render(&SUDO),
            "+Aa:BbC:c:D:Eeg:Hh:iKklNnPp:R:r:SsT:t:U:u:Vv askpass|A auth-type=|a \
             background|b bell|B close-from=|C login-class=|c chdir=|D preserve-env[=]|E \
             edit|e group=|g set-home|H help|h host= login|i remove-timestamp|K \
             reset-timestamp|k list|l non-interactive|n no-update|N preserve-groups|P \
             prompt=|p chroot=|R role=|r stdin|S shell|s type=|t command-timeout=|T \
             other-user=|U user=|u version|V validate|v"
        );
        peels_every_option("sudo", None);
    }

    /// `command` skips every leading `-` word; `builtin` has no options.
    #[test]
    fn pin_command_and_builtin() {
        assert!(spec("command").is_none() && spec("builtin").is_none());
        let seg: Vec<Word> = ["command", "-p", "-v", "rm", "-rf"].map(w).to_vec();
        assert_eq!(texts(unwrap_transparent_prefix(&seg)), ["rm", "-rf"]);
        let seg: Vec<Word> = ["builtin", "cd", "/"].map(w).to_vec();
        assert_eq!(texts(unwrap_transparent_prefix(&seg)), ["cd", "/"]);
    }

    /// F2: `wrapper_reads` resolves `--arg-file` like getopt.
    #[test]
    fn xargs_reads_follow_getopt() {
        let reads = |s: &str| {
            let seg: Vec<Word> = s.split(' ').map(w).collect();
            wrapper_reads(&seg)
                .into_iter()
                .map(|(f, _)| f)
                .collect::<Vec<_>>()
        };
        for s in [
            "xargs --arg-file F echo",
            "xargs --arg-f F echo",
            "xargs --arg F echo",
            "xargs --a F echo",
            "xargs --ar=F echo",
            "xargs -0a F echo",
            "xargs -aF echo",
            "nice xargs -ta F echo",
        ] {
            assert_eq!(reads(s), ["F"], "{s}");
        }
        assert!(reads("xargs -I a echo").is_empty());
        assert!(reads("xargs --delimiter a echo").is_empty());
        assert!(reads("echo -a F").is_empty());
    }
}
