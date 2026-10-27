//! Pack model + TOML loader.
//!
//! A pack is metadata plus an allow-regex list and a deny-regex list, each deny
//! carrying a human-readable reason, plus optional path rules
//! (`[[deny_path]]` / `[[allow_path]]`, see `crate::pathrule`) judged against
//! the files a tool or command touches. Loading is fail-open at the granularity of
//! the failure: an uncompilable regex drops that *rule* (with a warning), a
//! malformed or duplicate-id file drops that *pack* (with a warning) — neither
//! aborts the load of the rest.
//!
//! Pack file schema (unknown keys are a load error):
//!
//! ```toml
//! [pack]        # id, name, description, default_on, version, triggers,
//!               # substitution_failsafe
//! [[allow]] / [[deny]]
//! pattern = "regex"           # matched against the effective command line
//! reason = "..."              # required for deny
//! whole_segment = true        # match the whole segment instead: wrappers
//!                             # (`env`, `sudo`) and leading `NAME=value`
//!                             # assignments included
//! after_env_change = true     # only after an earlier segment of the same
//!                             # command line changed PATH/HOME/XDG_DATA_HOME
//! peeled_wrappers = true      # match the names of the wrappers peeled off
//!                             # in front of the command instead, joined
//!                             # with spaces (`timeout 5 sudo ls`:
//!                             # `timeout sudo`); never matches without one
//! operand_match = "regex|glob" # also require an operand, read as a
//! operand_targets = ["x"]     # pattern of this syntax, to match a target
//! operand_match_share = 0.8   # the operand must match this share of the
//!                             # targets instead of one
//! operand_min_len = 2         # a shorter operand (empty too) is a match
//! operand_substitution = true # an operand holding `$(…)` is a match
//! no_redirections = true      # match the effective command without its
//!                             # redirections (`2>&1` is not an argument)
//! when_option = ["-f", "--full"] # also require one of these options,
//! command_options = "fq:"     # read with getopt from the command's own
//! command_long_options = ["full|f", "queue=|q", "eof[=]"] # options
//!                             # (`name=` takes a value, `name[=]` an
//!                             # attached one; `|c` is the short alias)
//! command_signal_word = true  # the first `-SIGNAL` word is not options
//! command_long_only = true    # `-name` may be a long option too
//! when_no_operand = true      # also require that the command has no
//!                             # operand (after getopt); a word that may be
//!                             # a signal or options is read both ways
//! [[allow_path]] / [[deny_path]]
//! glob = "~/.ssh/id_*"        # see `crate::pathrule`
//! access = "read|write|any"
//! ancestors = true            # deny_path only: match the proper ancestors
//!                             # of a variable-rooted, wildcard-free glob
//!                             # (write access), e.g. `rm -rf ~/.local/share`
//! ```
//!
//! An `[[allow]]` match exempts the command only from its own pack's
//! `[[deny]]` rules (as `[[allow_path]]` does for paths); other packs still
//! judge it, and their first deny wins.

use std::cell::Cell;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use regex::Regex;
use serde::Deserialize;

use crate::getopt::{Opt, OwnedSpec};
use crate::pathrule::{validate_ancestors, validate_glob, PathRule, RuleAccess};
use crate::prefilter::Prefilter;

/// A compiled matching rule: a regex plus the reason shown when it fires.
#[derive(Debug, Clone)]
pub struct Rule {
    /// The rule's name within its pack (`force-push`), for `[guard] ask`
    /// (`core.git/force-push`): see [`valid_rule_id`]; unique in the pack.
    /// Optional; a rule without one cannot be put under `ask`.
    pub id: Option<String>,
    pub pattern: String,
    pub regex: Regex,
    pub reason: String,
    /// Match against the whole segment (wrappers such as `env`/`sudo` and
    /// leading `NAME=value` assignments included) instead of the effective
    /// command after them.
    pub whole_segment: bool,
    /// Applies only to a command that comes after an earlier segment of the
    /// same command line exported or assigned `PATH` (other than appending
    /// to it), `HOME` or `XDG_DATA_HOME`; matches the effective command.
    pub after_env_change: bool,
    /// Match the names of the transparent wrappers peeled off in front of
    /// the effective command (`timeout 5 xargs sudo ls`: `timeout xargs
    /// sudo`) instead. Never matches a segment without wrappers.
    pub peeled_wrappers: bool,
    /// Match the effective command without its redirections (`kill 1234
    /// 2>&1` is `kill 1234`).
    pub no_redirections: bool,
    /// Also required: an operand of the command, read as a pattern, matches
    /// one of the targets (`pkill 'sa.*fed'` names `saiifed`).
    pub operands: Option<OperandMatch>,
    /// Also required: the command was given one of these options, read
    /// with getopt from the command's own option table (`pkill -f`,
    /// `--full`, `--f`, `-9f`).
    pub when_option: Option<WhenOption>,
    /// The command's option table (`command_options`,
    /// `command_long_options`), when the rule has one: `operands` then
    /// reads the operands with getopt, so option values (`pkill -u 0
    /// node`, `--signal 9`) are not operands.
    pub table: Option<WhenOption>,
}

/// `when_option`, `command_options` and `command_long_options` of a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhenOption {
    pub spec: OwnedSpec,
    /// `-f` (short) and `--full` (long, full name) spellings.
    pub names: Vec<String>,
    /// The command takes its signal as a `-SIGNAL` word before reading its
    /// options (`pkill -TERM`, `killall -9`): the first such word is not
    /// read as options (`command_signal_word = true`).
    pub signal_word: bool,
    /// The command reads options with `getopt_long_only`: `-name` may be a
    /// long option too (`killall -regexp`; `command_long_only = true`).
    pub long_only: bool,
    /// Also required: the command has no operand (`when_no_operand =
    /// true`; `pkill -n`). The `-SIGNAL` word is then read both ways, as a
    /// signal and as options, and the rule matches if either reading does.
    pub no_operand: bool,
    /// Options whose value names a target (`target_options`; `pkill -P
    /// 1234`): with `no_operand`, a command given one of them with a
    /// target value ([`names_target`]) has a target, and the rule does not
    /// match.
    pub targets: Vec<String>,
}

fn strs(words: &[String]) -> Vec<&str> {
    words.iter().map(String::as_str).collect()
}

/// Does an option value name a specific target: a comma list of literal
/// pids, process groups or sessions above 1 (`0` is the caller's own group
/// or session, `1` init), or `$$` (the shell's own pid)? An expansion other
/// than `$$`, a glob, a name or an empty value names none.
pub fn names_target(value: &str) -> bool {
    !value.is_empty()
        && value.split(',').all(|v| {
            v == "$$"
                || (!v.is_empty()
                    && v.len() <= 10
                    && v.bytes().all(|b| b.is_ascii_digit())
                    && v.parse::<u64>().is_ok_and(|n| n > 1))
        })
}

/// Linux signal names (`/usr/include/bits/signum-generic.h` and
/// `signum-arch.h`; the `signal(7)` list), without `SIG`.
const SIGNAL_NAMES: &[&str] = &[
    "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "IOT", "BUS", "FPE", "KILL", "USR1", "SEGV",
    "USR2", "PIPE", "ALRM", "TERM", "STKFLT", "CHLD", "CLD", "CONT", "STOP", "TSTP", "TTIN",
    "TTOU", "URG", "XCPU", "XFSZ", "VTALRM", "PROF", "WINCH", "IO", "POLL", "PWR", "SYS", "RTMIN",
    "RTMAX",
];

/// Is `word` a `-SIGNAL` word: `-` and a signal number, or a signal name
/// (any case, optional `SIG` prefix, `RTMIN+n`/`RTMAX-n`)?
pub fn is_signal_word(word: &str) -> bool {
    let Some(sig) = word.strip_prefix('-') else {
        return false;
    };
    if !sig.is_empty() && sig.len() <= 3 && sig.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    let upper = sig.to_ascii_uppercase();
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    let name = match name.split_once(['+', '-']) {
        Some((base @ ("RTMIN" | "RTMAX"), n))
            if !n.is_empty() && n.len() <= 2 && n.bytes().all(|b| b.is_ascii_digit()) =>
        {
            base
        }
        Some(_) => return false,
        None => name,
    };
    SIGNAL_NAMES.contains(&name)
}

impl WhenOption {
    /// Was one of the options given? Options are read anywhere among the
    /// arguments (getopt permutes), up to `--`. Fails closed:
    /// - a long option the command does not know, or an ambiguous prefix,
    ///   counts as given (the command refuses it; a newer one may know it);
    /// - a value word that starts with `-` is also read as options
    ///   (`pkill -IO -f`: whatever `-IO` means, `-f` is seen);
    /// - with `long_only`, a `-word` is read both as a long option and as
    ///   a short bundle.
    ///
    /// With `signal_word`, a leading `-SIGNAL` word (only the first
    /// argument: pkill and killall look at no other) is read both ways: as
    /// the signal, and as options (`killall -rtmin x` may be `-r` …).
    /// Either reading giving the option is a match.
    pub fn given(&self, args: &[String]) -> bool {
        self.readings(args)
            .iter()
            .any(|r| self.given_in(&strs(r)).0)
    }

    /// The ways `args` may be read: without a leading `-SIGNAL` word (when
    /// the command takes one and it is there), and as written.
    /// The leading word is also read in lower case when that differs (how
    /// the tool turns a signal name it does not take back into options is
    /// not modelled: `killall -RTMIN` may be read as `-rtmin`).
    fn readings(&self, args: &[String]) -> Vec<Vec<String>> {
        let words: Vec<String> = args.to_vec();
        let mut out = Vec::with_capacity(3);
        if self.signal_word && words.first().is_some_and(|w| is_signal_word(w)) {
            out.push(words[1..].to_vec());
            let lower = words[0].to_ascii_lowercase();
            if lower != words[0] {
                let mut l = words.clone();
                l[0] = lower;
                out.push(l);
            }
        }
        out.push(words);
        out
    }

    /// The rule's whole option test: `given`, and with `no_operand` also
    /// no operand and no option naming a target (`targets`). A leading
    /// `-SIGNAL` word is read both ways (fails closed: `pkill -ttin` is
    /// SIGTTIN, or `-t tin`), and either reading matching is a match.
    pub fn matches(&self, args: &[String]) -> bool {
        if !self.no_operand {
            return self.given(args);
        }
        self.readings(args).iter().any(|r| {
            let r = strs(r);
            let (hit, targeted) = self.given_in(&r);
            hit && !targeted && !self.has_operand(&r)
        })
    }

    /// The operands of `args`, read with getopt (option values are not
    /// operands, unless they hold a command substitution), as `--`
    /// followed by every operand of any reading (fails closed: more
    /// operands, more to match). With `long_only`, a `-word`
    /// that may be a long option taking the next word is read as not
    /// taking it, so that word is an operand too.
    pub fn operand_args(&self, args: &[String]) -> Vec<String> {
        let mut out = vec!["--".to_string()];
        for r in self.readings(args) {
            for o in self.operands_in(&strs(&r)) {
                if !out[1..].iter().any(|x| x == o) {
                    out.push(o.to_string());
                }
            }
        }
        // A command substitution may split into several words, operands
        // among them, wherever it stands (`pkill -u $(…) node`): it stays
        // an operand.
        for a in args {
            if (a.contains("$(") || a.contains('`')) && !out[1..].contains(a) {
                out.push(a.clone());
            }
        }
        out
    }

    fn operands_in<'w>(&self, words: &[&'w str]) -> Vec<&'w str> {
        self.spec.with(|spec| {
            let mut out = Vec::new();
            let mut i = 0;
            while i < words.len() {
                let w = words[i];
                if w == "--" {
                    out.extend_from_slice(&words[i + 1..]);
                    break;
                }
                // An unknown or ambiguous long option is refused by the
                // tool; whether it would take the next word is unknown, so
                // that word is read as an operand too (fails closed).
                let mut unknown = false;
                match spec.option_at(words, i, &mut |o| {
                    unknown |= matches!(o, Opt::Unknown { .. })
                }) {
                    Some(_) if unknown => i += 1,
                    Some(n) => i = n,
                    None => {
                        out.push(w);
                        i += 1;
                    }
                }
            }
            out
        })
    }

    /// Does `words` hold an operand? Read with getopt, permuting, up to
    /// `--` (any word after it is an operand). Fails closed towards "no
    /// operand": a word is skipped as a value when any reading takes it
    /// as one (with `long_only`, `-user x` as `--user x`).
    fn has_operand(&self, words: &[&str]) -> bool {
        self.spec.with(|spec| {
            let mut i = 0;
            while i < words.len() {
                let w = words[i];
                if w == "--" {
                    return i + 1 < words.len();
                }
                let mut next = spec.option_at(words, i, &mut |_| {});
                if self.long_only && w.len() > 2 && !w.starts_with("--") && w.starts_with('-') {
                    let (name, attached) = match w[1..].split_once('=') {
                        Some((n, _)) => (n, true),
                        None => (&w[1..], false),
                    };
                    if let crate::getopt::Resolved::Known(o) = spec.resolve_long(name) {
                        let long_next = if o.arg == crate::getopt::Arg::Required && !attached {
                            i + 2
                        } else {
                            i + 1
                        };
                        next = Some(next.map_or(long_next, |n| n.max(long_next)));
                    }
                }
                match next {
                    Some(n) => i = n,
                    None => return true,
                }
            }
            false
        })
    }

    /// `given`, over one reading: whether one of `names` was given, and
    /// whether the `targets` given name a target. Fails closed: every
    /// occurrence of a target option must name a target, and none may be
    /// given twice (short and long spelling share a slot), so a later
    /// `-P ''` cannot override an earlier `-P 1234`.
    fn given_in(&self, words: &[&str]) -> (bool, bool) {
        let named = |list: &[String], short: char, long: Option<&str>| {
            list.iter().any(|n| match n.strip_prefix("--") {
                Some(l) => long == Some(l),
                None => {
                    short != '\0'
                        && n.strip_prefix('-')
                            .is_some_and(|s| s.chars().eq(std::iter::once(short)))
                }
            })
        };
        self.spec.with(|spec| {
            let mut hit = false;
            let mut slots: Vec<String> = Vec::new();
            let mut target_bad = false;
            let mut seen = |o: Opt<'_, '_>| match o {
                Opt::Known {
                    short, long, value, ..
                } => {
                    hit |= named(&self.names, short, long);
                    if named(&self.targets, short, long) {
                        let slot = if short != '\0' {
                            short.to_string()
                        } else {
                            long.unwrap_or_default().to_string()
                        };
                        target_bad |= slots.contains(&slot) || !value.is_some_and(names_target);
                        slots.push(slot);
                    }
                }
                Opt::Unknown { .. } => hit = true,
            };
            let mut i = 0;
            while i < words.len() {
                let w = words[i];
                if w == "--" {
                    break;
                }
                if self.long_only && w.len() > 2 && !w.starts_with("--") && w.starts_with('-') {
                    let name = w[1..].split('=').next().unwrap_or("");
                    if let crate::getopt::Resolved::Known(o) = spec.resolve_long(name) {
                        seen(Opt::Known {
                            short: o.short,
                            long: Some(o.name),
                            value: None,
                            word: i,
                            separate: false,
                        });
                    }
                }
                let mut dash_value = false;
                match spec.option_at(words, i, &mut |o| {
                    if let Opt::Known {
                        value: Some(v),
                        separate: true,
                        ..
                    } = o
                    {
                        dash_value |= v.starts_with('-');
                    }
                    seen(o)
                }) {
                    Some(next) if dash_value => i = next - 1,
                    Some(next) => i = next,
                    None => i += 1,
                }
            }
            (hit, !slots.is_empty() && !target_bad)
        })
    }
}

/// How a command reads its operands as patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperandSyntax {
    /// A regular expression searched in the name (`pkill`, `killall -r`).
    Regex,
    /// A shell glob matched against the whole name (`systemctl`); only
    /// operands with `*`, `?` or `[` are read as patterns.
    Glob,
}

/// `operand_match` and `operand_targets` of a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperandMatch {
    pub syntax: OperandSyntax,
    pub targets: Vec<String>,
    /// How many targets one operand must match: 1, or the share the rule
    /// sets (`operand_match_share = 0.8`; `pkill .` matches every name).
    pub need: usize,
    /// An operand shorter than this many characters, empty included,
    /// counts as a match (`operand_min_len = 2`; `pkill e`); 0 for none.
    pub min_len: usize,
    /// An operand holding a command substitution or arithmetic counts as a
    /// match (`operand_substitution = true`; `pkill $(cat f)`).
    pub substitution: bool,
}

/// Largest compiled operand pattern (the regex NFA size limit); a bigger
/// one counts as a match. Patterns are compiled without Unicode (`\w`, `.`
/// and classes are ASCII or bytes; the targets are ASCII), which keeps a
/// 256-byte pattern far below this and its compile cheap.
const OPERAND_REGEX_LIMIT: usize = 64 << 10;
/// Most pattern operands compiled for one command; more count as a match.
pub const MAX_PATTERN_OPERANDS: usize = 32;
/// Longest pattern operand compiled; a longer one counts as a match.
pub const MAX_PATTERN_BYTES: usize = 256;
/// Most time spent compiling operand patterns in one evaluation (one
/// command line, nested lines included); once it is spent, every further
/// pattern counts as a match. Keeps hostile patterns well inside the
/// engine budget.
pub const MAX_PATTERN_COMPILE: Duration = Duration::from_millis(5);

/// Regex metacharacters: an operand without any is a plain substring.
const REGEX_META: &[char] = &[
    '.', '^', '$', '*', '+', '?', '(', ')', '[', ']', '{', '}', '|', '\\',
];
/// Glob metacharacters.
const GLOB_META: &[char] = &['*', '?', '['];

/// The answer of `OperandMatch::hits`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hit {
    Yes,
    No,
    /// The engine's budget ran out while compiling patterns.
    OutOfBudget,
}

impl OperandMatch {
    /// `Yes` if an operand matches enough targets (`need`; one unless the
    /// rule sets `operand_match_share`), case-insensitively. Operands are
    /// the words not starting with `-`, and every word after a `--`. A
    /// plain operand (no pattern characters) is a substring test (regex)
    /// or an equality test (glob), without compiling anything. These count
    /// as a match, since what the command makes of them is unknown or too
    /// costly to find out: a pattern that does not compile, a glob with `\`
    /// or `[:` (escapes and classes are not modelled), a pattern longer
    /// than `MAX_PATTERN_BYTES`, and more than `MAX_PATTERN_OPERANDS`
    /// patterns, and any pattern once `spent` (the evaluation's compile
    /// time so far) exceeds `MAX_PATTERN_COMPILE`. With `min_len`, an
    /// operand shorter than that (empty included) counts too; with
    /// `substitution`, an operand holding a `$(…)`, `` `…` `` or `$((…))`.
    /// `over_budget` is checked before each compile.
    pub fn hits(
        &self,
        operands: &[String],
        over_budget: &dyn Fn() -> bool,
        spent: &Cell<Duration>,
    ) -> Hit {
        self.hits_within(operands, over_budget, spent, MAX_PATTERN_COMPILE)
    }

    /// `hits`, with `allowance` in place of `MAX_PATTERN_COMPILE`.
    pub(crate) fn hits_within(
        &self,
        operands: &[String],
        over_budget: &dyn Fn() -> bool,
        spent: &Cell<Duration>,
        allowance: Duration,
    ) -> Hit {
        let mut compiled = 0;
        let need = self.need.max(1);
        // Enough targets pass `test`.
        let enough = |test: &dyn Fn(&str) -> bool| {
            self.targets.iter().filter(|t| test(t)).take(need).count() >= need
        };
        let dashdash = operands.iter().position(|o| o == "--");
        let words = operands
            .iter()
            .enumerate()
            .filter(|(i, o)| match dashdash {
                Some(d) if *i > d => true,
                Some(d) if *i == d => false,
                _ => !o.starts_with('-'),
            })
            .map(|(_, o)| o);
        for o in words {
            if self.min_len > 0 && o.chars().count() < self.min_len {
                return Hit::Yes;
            }
            if self.substitution && (o.contains("$(") || o.contains('`') || o.contains("$[")) {
                return Hit::Yes;
            }
            // A parameter expansion is not known until the command runs
            // (empty, or anything): an operand holding one counts as a
            // match (`pkill "$X"`, `pkill "sa${X}fed"`). A bare `$$`, `$#`,
            // `$?` or `$!` is a number.
            if has_expansion(o) {
                return Hit::Yes;
            }
            if o.is_empty() {
                continue;
            }
            // Rust regex class set operations (`[a-z&&[^x]]`, `--`, `~~`)
            // mean nothing to POSIX ERE (pkill, killall) or fnmatch: what
            // the tool makes of them is not what the guard would judge.
            if has_class_set_op(o) {
                return Hit::Yes;
            }
            let lower = o.to_lowercase();
            let source = match self.syntax {
                OperandSyntax::Regex if !o.contains(REGEX_META) => {
                    if enough(&|t| t.to_lowercase().contains(&lower)) {
                        return Hit::Yes;
                    }
                    continue;
                }
                // `\` escapes (`sai\ifed` is `saiifed`) and `[:class:]` are
                // not modelled.
                OperandSyntax::Glob if o.contains('\\') || o.contains("[:") => return Hit::Yes,
                OperandSyntax::Glob if !o.contains(GLOB_META) => {
                    if enough(&|t| t.to_lowercase() == lower) {
                        return Hit::Yes;
                    }
                    continue;
                }
                OperandSyntax::Regex => o.clone(),
                OperandSyntax::Glob => glob_regex(o),
            };
            compiled += 1;
            if compiled > MAX_PATTERN_OPERANDS
                || o.len() > MAX_PATTERN_BYTES
                || spent.get() > allowance
            {
                return Hit::Yes;
            }
            if over_budget() {
                return Hit::OutOfBudget;
            }
            let t0 = Instant::now();
            let built = regex::bytes::RegexBuilder::new(&source)
                .unicode(false)
                .case_insensitive(true)
                .size_limit(OPERAND_REGEX_LIMIT)
                .dfa_size_limit(OPERAND_REGEX_LIMIT)
                .build();
            spent.set(spent.get() + t0.elapsed());
            match built {
                Ok(re) if enough(&|t| re.is_match(t.as_bytes())) => return Hit::Yes,
                Ok(_) => {}
                Err(_) => return Hit::Yes,
            }
        }
        Hit::No
    }
}

/// Does `word` hold a parameter expansion (`$X`, `${…}`, `$1`, `$@`, …)?
/// A whole word of `$$`, `$#`, `$?` or `$!` does not count; a `$` before
/// anything else (`$(`, a lone `$`) is not one.
fn has_expansion(word: &str) -> bool {
    if matches!(word, "$$" | "$#" | "$?" | "$!") {
        return false;
    }
    let b = word.as_bytes();
    b.iter().enumerate().any(|(i, &c)| {
        c == b'$'
            && match b.get(i + 1) {
                Some(b'{') => true,
                Some(n) => {
                    n.is_ascii_alphanumeric()
                        || matches!(n, b'_' | b'@' | b'*' | b'!' | b'-' | b'$' | b'#' | b'?')
                }
                None => false,
            }
    })
}

/// Does a pattern operand hold a Rust regex class set operation (`&&`,
/// `--` or `~~` after a `[`)? Read loosely: any of them after any `[`.
fn has_class_set_op(o: &str) -> bool {
    o.find('[')
        .is_some_and(|i| ["&&", "--", "~~"].iter().any(|op| o[i..].contains(op)))
}

/// An anchored regex for a shell glob: `*`, `?`, and `[…]` classes (`[!…]`
/// negated); everything else literal. A class without its `]` is literal.
fn glob_regex(glob: &str) -> String {
    let mut out = String::from("^");
    let chars: Vec<char> = glob.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            '[' => {
                let close = chars[i + 1..]
                    .iter()
                    .skip(1)
                    .position(|&c| c == ']')
                    .map(|p| i + 2 + p);
                let Some(end) = close else {
                    out.push_str("\\[");
                    i += 1;
                    continue;
                };
                let mut class: String = chars[i + 1..end].iter().collect();
                if let Some(rest) = class.strip_prefix('!') {
                    class = format!("^{rest}");
                }
                out.push('[');
                // `&`, `~` (and `[`, `\`) are escaped one by one: Rust
                // regex reads `&&` and `~~` in a class as set operations.
                out.push_str(
                    &class
                        .replace('\\', "\\\\")
                        .replace('[', "\\[")
                        .replace('&', "\\&")
                        .replace('~', "\\~"),
                );
                out.push(']');
                i = end;
            }
            c => out.push_str(&regex::escape(&c.to_string())),
        }
        i += 1;
    }
    out.push('$');
    out
}

/// A loaded, compiled pack.
#[derive(Debug, Clone)]
pub struct Pack {
    pub id: String,
    pub name: String,
    pub description: String,
    pub default_on: bool,
    pub version: u32,
    pub triggers: Vec<String>,
    /// A command this pack has deny rules for is blocked when an argument
    /// is a command substitution (`rm -rf $(…)`). Packs whose triggers are
    /// everyday tools (`gh`, `kubectl`) turn this off.
    pub substitution_failsafe: bool,
    pub allow: Vec<Rule>,
    pub deny: Vec<Rule>,
    /// Path carve-outs: a path matching one is exempt from THIS pack's
    /// `deny_path` rules (never from another pack's).
    pub allow_path: Vec<PathRule>,
    pub deny_path: Vec<PathRule>,
    /// Built once from `triggers` at load.
    prefilter: Prefilter,
    /// `[pack] lazy = true` from a catalog: `allow` and `deny` are empty
    /// and the rules are compiled on first use ([`Pack::allow_rules`],
    /// [`Pack::deny_rules`]), which the engine asks for only when a command
    /// line holds one of the pack's triggers.
    lazy: Option<std::sync::Arc<LazyRules>>,
}

/// The rules of a lazy pack, compiled once on first use.
#[derive(Debug)]
struct LazyRules {
    source: &'static str,
    toml: &'static str,
    has_deny: bool,
    rules: std::sync::OnceLock<(Vec<Rule>, Vec<Rule>)>,
}

impl LazyRules {
    fn get(&self) -> &(Vec<Rule>, Vec<Rule>) {
        self.rules.get_or_init(|| {
            // A broken built-in drops its rules, as an eager load does;
            // `load_all` (eager) reports it, and the tests keep every
            // built-in loading clean.
            let mut warnings = Vec::new();
            match load_pack_str(self.source, self.toml, &mut warnings) {
                Ok(p) => (p.allow, p.deny),
                Err(_) => (Vec::new(), Vec::new()),
            }
        })
    }
}

impl Pack {
    /// The pack's pre-filter, built from its literal triggers.
    pub fn prefilter(&self) -> &Prefilter {
        &self.prefilter
    }

    /// The `[[allow]]` rules (compiled now, for a lazy pack).
    pub fn allow_rules(&self) -> &[Rule] {
        match &self.lazy {
            Some(l) => &l.get().0,
            None => &self.allow,
        }
    }

    /// The `[[deny]]` rules (compiled now, for a lazy pack).
    pub fn deny_rules(&self) -> &[Rule] {
        match &self.lazy {
            Some(l) => &l.get().1,
            None => &self.deny,
        }
    }

    /// The pack has `[[deny]]` rules, without compiling a lazy pack.
    pub fn has_deny(&self) -> bool {
        match &self.lazy {
            Some(l) => l.has_deny,
            None => !self.deny.is_empty(),
        }
    }

    /// This pack without the `[[deny]]` rules whose id is in `ids` (a lazy
    /// pack is compiled now). For telling whether a call is denied only
    /// by `[guard] ask` rules.
    pub fn without_deny_ids(&self, ids: &[&str]) -> Pack {
        let mut p = self.clone();
        p.allow = self.allow_rules().to_vec();
        p.deny = self
            .deny_rules()
            .iter()
            .filter(|r| r.id.as_deref().is_none_or(|i| !ids.contains(&i)))
            .cloned()
            .collect();
        p.lazy = None;
        p
    }

    /// This pack with only its `[[deny]]` rule `id` (its `[[allow]]`
    /// carve-outs kept, no path rules), or `None` if it has no such rule.
    /// For checking that a claimed rule really matches a command.
    pub fn only_deny_id(&self, id: &str) -> Option<Pack> {
        let rule = self
            .deny_rules()
            .iter()
            .find(|r| r.id.as_deref() == Some(id))?
            .clone();
        let mut p = self.clone();
        p.allow = self.allow_rules().to_vec();
        p.deny = vec![rule];
        p.allow_path = Vec::new();
        p.deny_path = Vec::new();
        p.lazy = None;
        Some(p)
    }

    /// The rules are compiled on first use.
    pub fn is_lazy(&self) -> bool {
        self.lazy.is_some()
    }

    /// Command rules plus path rules.
    pub fn rule_count(&self) -> usize {
        self.allow_rules().len()
            + self.deny_rules().len()
            + self.allow_path.len()
            + self.deny_path.len()
    }
}

/// A non-fatal problem encountered while loading (surfaced, never silent).
#[derive(Debug, Clone)]
pub struct PackWarning {
    pub source: String,
    pub message: String,
}

impl PackError {
    /// The TOML and `[pack]` header were fine; a rule is what broke the pack.
    pub fn is_broken_rule(&self) -> bool {
        matches!(self, Self::MissingReason(_) | Self::NoRules)
    }
}

/// A fatal problem for a single pack file (the file is skipped; others load).
#[derive(Debug, thiserror::Error)]
pub enum PackError {
    #[error("invalid pack TOML: {0}")]
    Toml(String),
    #[error("pack is missing a deny reason for {0:?}")]
    MissingReason(String),
    #[error("pack has no id")]
    MissingId,
    #[error("no usable rules after compilation")]
    NoRules,
}

// ---- Raw (deserialized) shape ------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawPackFile {
    pack: RawMeta,
    #[serde(default)]
    allow: Vec<RawRule>,
    #[serde(default)]
    deny: Vec<RawRule>,
    #[serde(default)]
    allow_path: Vec<RawPathRule>,
    #[serde(default)]
    deny_path: Vec<RawPathRule>,
}

#[derive(Debug, Deserialize)]
struct RawMeta {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default = "default_true")]
    default_on: bool,
    #[serde(default = "default_version")]
    version: u32,
    #[serde(default)]
    triggers: Vec<String>,
    #[serde(default = "default_true")]
    substitution_failsafe: bool,
    /// Compile the rules on first use (a catalog load; see [`Pack::lazy`]).
    #[serde(default)]
    #[allow(dead_code)] // read by `peek_header`
    lazy: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    #[serde(default)]
    id: Option<String>,
    pattern: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    whole_segment: bool,
    #[serde(default)]
    after_env_change: bool,
    #[serde(default)]
    peeled_wrappers: bool,
    #[serde(default)]
    operand_match: Option<OperandSyntax>,
    #[serde(default)]
    operand_targets: Vec<String>,
    #[serde(default)]
    when_option: Vec<String>,
    #[serde(default)]
    command_options: Option<String>,
    #[serde(default)]
    command_long_options: Vec<String>,
    #[serde(default)]
    command_signal_word: bool,
    #[serde(default)]
    command_long_only: bool,
    #[serde(default)]
    when_no_operand: bool,
    #[serde(default)]
    target_options: Vec<String>,
    #[serde(default)]
    operand_match_share: Option<f64>,
    #[serde(default)]
    operand_min_len: usize,
    #[serde(default)]
    operand_substitution: bool,
    #[serde(default)]
    no_redirections: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPathRule {
    glob: String,
    #[serde(default = "default_access")]
    access: RuleAccess,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    ancestors: bool,
}

fn default_access() -> RuleAccess {
    RuleAccess::Any
}

fn default_true() -> bool {
    true
}
fn default_version() -> u32 {
    1
}

// ---- Loading -----------------------------------------------------------------

/// Compile a rule list. A rule whose regex fails to compile is dropped with a
/// warning. For deny rules, a missing reason is a hard error (fail-open matters
/// only when the guard malfunctions, not when a rule is authored to block
/// without telling the user why). `require_reason` distinguishes deny vs allow.
fn compile_rules(
    source: &str,
    raw: Vec<RawRule>,
    require_reason: bool,
    warnings: &mut Vec<PackWarning>,
) -> Result<Vec<Rule>, PackError> {
    let mut out = Vec::with_capacity(raw.len());
    let mut ids = std::collections::HashSet::new();
    for mut r in raw {
        // A bad or repeated id is dropped, never the rule (that would
        // fail open).
        if let Some(id) = r.id.take() {
            if !valid_rule_id(&id) {
                warnings.push(PackWarning {
                    source: source.to_string(),
                    message: format!(
                        "rule {:?}: id {id:?} ignored (lowercase letters, digits and -)",
                        r.pattern
                    ),
                });
            } else if !ids.insert(id.clone()) {
                warnings.push(PackWarning {
                    source: source.to_string(),
                    message: format!("rule {:?}: id {id:?} ignored (used twice)", r.pattern),
                });
            } else {
                r.id = Some(id);
            }
        }
        if require_reason && r.reason.as_deref().unwrap_or("").trim().is_empty() {
            return Err(PackError::MissingReason(r.pattern));
        }
        let share_ok = r.operand_match_share.is_none_or(|x| x > 0.0 && x <= 1.0);
        let extras =
            r.operand_match_share.is_some() || r.operand_min_len > 0 || r.operand_substitution;
        let operands = match (r.operand_match, r.operand_targets.is_empty()) {
            (Some(syntax), false) if share_ok => {
                let n = r.operand_targets.len();
                let need = r
                    .operand_match_share
                    .map_or(1, |x| ((x * n as f64).ceil() as usize).clamp(1, n));
                Some(OperandMatch {
                    syntax,
                    targets: r.operand_targets,
                    need,
                    min_len: r.operand_min_len,
                    substitution: r.operand_substitution,
                })
            }
            (None, true) if !extras => None,
            _ => {
                warnings.push(PackWarning {
                    source: source.to_string(),
                    message: format!(
                        "skipping rule {:?}: operand_match and operand_targets go together \
                         (the other operand_ keys need them; a share is in (0, 1])",
                        r.pattern
                    ),
                });
                continue;
            }
        };
        let has_table = r.command_options.is_some() || !r.command_long_options.is_empty();
        let gates = !r.when_option.is_empty() || r.when_no_operand;
        // A table without `when_option` reads the operands of an operand
        // rule; `target_options` needs `when_no_operand`.
        let table_use_ok = (gates || operands.is_some())
            && (!r.when_no_operand || !r.when_option.is_empty())
            && (r.target_options.is_empty() || r.when_no_operand);
        let table = match (gates, has_table) {
            (false, false) if r.target_options.is_empty() => None,
            (_, true) if table_use_ok => {
                let names_ok = r.when_option.iter().chain(&r.target_options).all(|n| {
                    n.strip_prefix("--").is_some_and(|l| !l.is_empty())
                        || n.strip_prefix('-').is_some_and(|s| s.chars().count() == 1)
                });
                let spec = OwnedSpec::parse(
                    r.command_options.as_deref().unwrap_or(""),
                    &r.command_long_options,
                );
                match spec {
                    Ok(spec) if names_ok => Some(WhenOption {
                        spec,
                        names: r.when_option,
                        signal_word: r.command_signal_word,
                        long_only: r.command_long_only,
                        no_operand: r.when_no_operand,
                        targets: r.target_options,
                    }),
                    Ok(_) => {
                        warnings.push(PackWarning {
                            source: source.to_string(),
                            message: format!(
                                "skipping rule {:?}: when_option names are `-x` or `--name`",
                                r.pattern
                            ),
                        });
                        continue;
                    }
                    Err(e) => {
                        warnings.push(PackWarning {
                            source: source.to_string(),
                            message: format!("skipping rule {:?}: {e}", r.pattern),
                        });
                        continue;
                    }
                }
            }
            _ => {
                warnings.push(PackWarning {
                    source: source.to_string(),
                    message: format!(
                        "skipping rule {:?}: when_option needs command_options or \
                         command_long_options, and they need it or operand_match \
                         (when_no_operand needs all of them; target_options needs \
                         when_no_operand)",
                        r.pattern
                    ),
                });
                continue;
            }
        };
        let when_option = table.clone().filter(|_| gates);
        match Regex::new(&r.pattern) {
            Ok(regex) => out.push(Rule {
                id: r.id,
                when_option,
                table,
                pattern: r.pattern,
                regex,
                reason: r.reason.unwrap_or_default(),
                whole_segment: r.whole_segment,
                after_env_change: r.after_env_change,
                peeled_wrappers: r.peeled_wrappers,
                no_redirections: r.no_redirections,
                operands,
            }),
            Err(e) => warnings.push(PackWarning {
                source: source.to_string(),
                message: format!("skipping uncompilable regex {:?}: {e}", r.pattern),
            }),
        }
    }
    Ok(out)
}

/// A rule id: 1 to 64 of `a-z`, `0-9` and `-`, not starting with `-`.
pub fn valid_rule_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && !id.starts_with('-')
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Check a path rule list. A rule with a bad glob is dropped with a warning;
/// a deny rule without a reason is a hard error (as for `[[deny]]`).
fn check_path_rules(
    source: &str,
    raw: Vec<RawPathRule>,
    require_reason: bool,
    warnings: &mut Vec<PackWarning>,
) -> Result<Vec<PathRule>, PackError> {
    let mut out = Vec::with_capacity(raw.len());
    for r in raw {
        if require_reason && r.reason.as_deref().unwrap_or("").trim().is_empty() {
            return Err(PackError::MissingReason(r.glob));
        }
        let valid = if r.ancestors {
            validate_ancestors(&r.glob, r.access)
        } else {
            validate_glob(&r.glob)
        };
        match valid {
            Ok(()) => out.push(PathRule {
                glob: r.glob,
                access: r.access,
                reason: r.reason.unwrap_or_default(),
                ancestors: r.ancestors,
            }),
            Err(e) => warnings.push(PackWarning {
                source: source.to_string(),
                message: format!("skipping path rule: {e}"),
            }),
        }
    }
    Ok(out)
}

#[derive(Deserialize)]
struct RawHeader {
    pack: RawHeaderMeta,
    #[serde(default)]
    deny: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    allow_path: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    deny_path: Vec<serde::de::IgnoredAny>,
}

#[derive(Deserialize)]
struct RawHeaderMeta {
    id: String,
    #[serde(default = "default_true")]
    default_on: bool,
    #[serde(default = "default_version")]
    version: u32,
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    triggers: Vec<String>,
    #[serde(default = "default_true")]
    substitution_failsafe: bool,
    #[serde(default)]
    lazy: bool,
}

/// What a lazy pack needs before its rules are compiled.
#[derive(Debug, Clone)]
pub(crate) struct LazyMeta {
    name: String,
    description: String,
    triggers: Vec<String>,
    substitution_failsafe: bool,
    has_deny: bool,
}

/// A pack's `id`, `default_on` and `version` without compiling any of its
/// rules, so a caller can decide whether the pack is needed, and, for a
/// pack that says `lazy = true` (with triggers and no path rules), what
/// [`lazy_pack`] needs. `None` if the TOML or its `[pack]` table cannot be
/// read (a full load reports why).
pub(crate) fn peek_header(toml_str: &str) -> Option<((String, bool, u32), Option<LazyMeta>)> {
    let h: RawHeader = toml::from_str(toml_str).ok()?;
    if h.pack.id.trim().is_empty() {
        return None;
    }
    let lazy = (h.pack.lazy
        && !h.pack.triggers.is_empty()
        && h.allow_path.is_empty()
        && h.deny_path.is_empty())
    .then_some(LazyMeta {
        name: h.pack.name,
        description: h.pack.description,
        triggers: h.pack.triggers,
        substitution_failsafe: h.pack.substitution_failsafe,
        has_deny: !h.deny.is_empty(),
    });
    Some(((h.pack.id, h.pack.default_on, h.pack.version), lazy))
}

/// A pack whose rules are compiled on first use, from its peeked header.
pub(crate) fn lazy_pack(
    source: &'static str,
    toml: &'static str,
    (id, default_on, version): &(String, bool, u32),
    meta: &LazyMeta,
) -> Pack {
    Pack {
        prefilter: Prefilter::new(meta.triggers.clone()),
        id: id.clone(),
        name: meta.name.clone(),
        description: meta.description.clone(),
        default_on: *default_on,
        version: *version,
        triggers: meta.triggers.clone(),
        substitution_failsafe: meta.substitution_failsafe,
        allow: Vec::new(),
        deny: Vec::new(),
        allow_path: Vec::new(),
        deny_path: Vec::new(),
        lazy: Some(std::sync::Arc::new(LazyRules {
            source,
            toml,
            has_deny: meta.has_deny,
            rules: std::sync::OnceLock::new(),
        })),
    }
}

#[cfg(test)]
thread_local! {
    static COMPILED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many packs `load_pack_str` was asked to compile on this thread.
#[cfg(test)]
pub(crate) fn compiled_packs() -> usize {
    COMPILED.with(|c| c.get())
}

/// Load and compile a single pack from a TOML string. `source` labels the pack
/// in any warnings (a filename, or `"<builtin>"`).
pub fn load_pack_str(
    source: &str,
    toml_str: &str,
    warnings: &mut Vec<PackWarning>,
) -> Result<Pack, PackError> {
    #[cfg(test)]
    COMPILED.with(|c| c.set(c.get() + 1));
    let raw: RawPackFile = toml::from_str(toml_str).map_err(|e| PackError::Toml(e.to_string()))?;
    if raw.pack.id.trim().is_empty() {
        return Err(PackError::MissingId);
    }
    let allow = compile_rules(source, raw.allow, false, warnings)?;
    let deny = compile_rules(source, raw.deny, true, warnings)?;
    let allow_path = check_path_rules(source, raw.allow_path, false, warnings)?;
    let deny_path = check_path_rules(source, raw.deny_path, true, warnings)?;
    if allow.is_empty() && deny.is_empty() && allow_path.is_empty() && deny_path.is_empty() {
        return Err(PackError::NoRules);
    }
    Ok(Pack {
        prefilter: Prefilter::new(raw.pack.triggers.clone()),
        id: raw.pack.id,
        name: raw.pack.name,
        description: raw.pack.description,
        default_on: raw.pack.default_on,
        version: raw.pack.version,
        triggers: raw.pack.triggers,
        substitution_failsafe: raw.pack.substitution_failsafe,
        allow,
        deny,
        allow_path,
        deny_path,
        lazy: None,
    })
}

/// Load every `*.toml` under `dir`, fail-open. A malformed file is skipped with
/// a warning; a duplicate `id` is skipped with a warning (first wins).
pub fn load_packs_dir(dir: &Path) -> (Vec<Pack>, Vec<PackWarning>) {
    let mut packs: Vec<Pack> = Vec::new();
    let mut warnings: Vec<PackWarning> = Vec::new();

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            warnings.push(PackWarning {
                source: dir.display().to_string(),
                message: format!("cannot read packs dir: {e}"),
            });
            return (packs, warnings);
        }
    };

    let mut files: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "toml").unwrap_or(false))
        .collect();
    files.sort();

    for path in files {
        let source = path.display().to_string();
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                warnings.push(PackWarning {
                    source,
                    message: format!("cannot read file: {e}"),
                });
                continue;
            }
        };
        match load_pack_str(&source, &text, &mut warnings) {
            Ok(pack) => {
                if packs.iter().any(|p| p.id == pack.id) {
                    warnings.push(PackWarning {
                        source,
                        message: format!("duplicate pack id {:?}; skipping", pack.id),
                    });
                    continue;
                }
                packs.push(pack);
            }
            Err(e) => warnings.push(PackWarning {
                source,
                message: format!("skipping pack: {e}"),
            }),
        }
    }

    (packs, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_regex_translates_shell_globs() {
        assert_eq!(glob_regex("s*d.service"), r"^s.*d\.service$");
        assert_eq!(glob_regex("sa?"), "^sa.$");
        assert_eq!(glob_regex("[!x]y"), "^[^x]y$");
        assert_eq!(glob_regex("[]a]"), "^[]a]$");
        assert_eq!(glob_regex("a[b"), r"^a\[b$");
    }

    #[test]
    fn operand_match_reads_operands_as_patterns() {
        let m = |syntax, ops: &[&str]| {
            OperandMatch {
                syntax,
                targets: vec!["saiifed".into(), "saiifed.service".into()],
                need: 1,
                min_len: 0,
                substitution: false,
            }
            // No compile-time allowance: the caps tested here must not
            // depend on how fast a loaded runner compiles (M7).
            .hits_within(
                &ops.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                &|| false,
                &Cell::default(),
                Duration::MAX,
            ) == Hit::Yes
        };
        assert!(m(OperandSyntax::Regex, &["sa.*fed"]));
        assert!(m(OperandSyntax::Regex, &["-f", "S[A]IIFED"]));
        assert!(m(OperandSyntax::Regex, &["foo("]));
        assert!(m(OperandSyntax::Regex, &["IIFE"]), "plain: substring");
        assert!(!m(OperandSyntax::Regex, &["sain", "-saiifed"]));
        assert!(m(OperandSyntax::Glob, &["stop", "*fed"]));
        assert!(m(OperandSyntax::Glob, &["s*d.service"]));
        assert!(
            m(OperandSyntax::Glob, &["stop", "SAIIFED"]),
            "plain: equality"
        );
        assert!(!m(OperandSyntax::Glob, &["stop", "saiife"]));
        assert!(!m(OperandSyntax::Glob, &["nginx*"]));
        // Not modelled: escapes and character classes count as a match.
        assert!(m(OperandSyntax::Glob, &["\\x*"]));
        assert!(m(OperandSyntax::Glob, &["[[:alpha:]]*"]));
        // Caps: a long pattern, or too many patterns.
        assert!(m(
            OperandSyntax::Regex,
            &[&format!("x{}.", "y".repeat(300))]
        ));
        let many: Vec<String> = (0..40).map(|i| format!("x{i}.")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(m(OperandSyntax::Regex, &many));
        assert!(!m(OperandSyntax::Regex, &many[..30]));
        // Budget.
        let om = OperandMatch {
            syntax: OperandSyntax::Regex,
            targets: vec!["saiifed".into()],
            need: 1,
            min_len: 0,
            substitution: false,
        };
        assert_eq!(
            om.hits(&["x.".to_string()], &|| true, &Cell::default()),
            Hit::OutOfBudget
        );
        // The evaluation's compile time is spent: any pattern is a match.
        let spent = Cell::new(MAX_PATTERN_COMPILE + Duration::from_millis(1));
        assert_eq!(om.hits(&["zz.".to_string()], &|| false, &spent), Hit::Yes);
        assert_eq!(
            om.hits(&["zz.".to_string()], &|| false, &Cell::default()),
            Hit::No
        );
    }

    /// Hostile sub-cap patterns compile quickly without Unicode classes:
    /// 32 of `\w{1,10}\dN` (which took milliseconds each with Unicode).
    #[test]
    fn hostile_patterns_compile_quickly() {
        let om = OperandMatch {
            syntax: OperandSyntax::Regex,
            targets: vec!["saiifed".into()],
            need: 1,
            min_len: 0,
            substitution: false,
        };
        let ops: Vec<String> = (0..31).map(|i| format!("\\w{{1,10}}\\d{i}")).collect();
        let spent = Cell::default();
        let t = Instant::now();
        let hit = om.hits(&ops, &|| false, &spent);
        eprintln!("31 patterns: {:?} (compile {:?})", t.elapsed(), spent.get());
        // None matches; only a loaded runner (compile allowance spent)
        // turns that into a match, never into a miss.
        assert!(
            hit == Hit::No || spent.get() > MAX_PATTERN_COMPILE,
            "{hit:?}"
        );
        // A size-limited pattern fails to compile: a match.
        assert_eq!(
            om.hits(
                &["(?:a{1,100}){1,100}x".into()],
                &|| false,
                &Cell::default()
            ),
            Hit::Yes
        );
    }

    #[test]
    fn when_option_reads_options_with_getopt() {
        let w = WhenOption {
            spec: OwnedSpec::parse(
                "Hq:emcfg:G:inoO:p:P:s:t:u:U:xF:Lr:AQhV",
                &[
                    "full|f".into(),
                    "signal=".into(),
                    "echo|e".into(),
                    "euid=|u".into(),
                ],
            )
            .unwrap(),
            names: vec!["-f".into(), "--full".into()],
            signal_word: true,
            long_only: false,
            no_operand: false,
            targets: Vec::new(),
        };
        let given = |s: &str| w.given(&s.split(' ').map(String::from).collect::<Vec<_>>());
        for yes in [
            "-f x",
            "--full x",
            "--f x",
            "--fu x",
            "--ful x",
            "x -f",
            "-9f x",
            "-ef x",
            "--e x",
            "--zz x",
            // Fix round 5 (B1): a `-SIGNAL` word is not read as options,
            // and a value starting with `-` is read as options too.
            "-IO -f x",
            "-TRAP -f x",
            "-TSTP -f x",
            "-SIGIO -f x",
            "-9 -f x",
            "-RTMIN+1 -f x",
            "-u -f x",
            "--signal -f x",
            "--eu -f x",
            "-qp -f x",
        ] {
            assert!(given(yes), "{yes}");
        }
        for no in [
            "x",
            "-qf x",
            "x -- -f",
            "-TERM x",
            "-q 1 x",
            "--signal HUP x",
        ] {
            assert!(!given(no), "{no}");
        }
    }

    #[test]
    fn signal_words() {
        for yes in [
            "-9",
            "-0",
            "-64",
            "-TERM",
            "-term",
            "-SIGIO",
            "-sigterm",
            "-RTMIN+1",
            "-RTMAX-2",
            "-SIGRTMIN",
            "-IOT",
        ] {
            assert!(is_signal_word(yes), "{yes}");
        }
        for no in [
            "-f", "-IOX", "-RTMIN+", "-HUP+1", "TERM", "-", "-1234", "-SIG",
        ] {
            assert!(!is_signal_word(no), "{no}");
        }
    }

    #[test]
    fn long_only_reads_dash_words_as_long_options() {
        let w = WhenOption {
            spec: OwnedSpec::parse(
                "eIgy:o:ilqrs:u:vVwn:Z:",
                &[
                    "regexp|r".into(),
                    "verbose|v".into(),
                    "version|V".into(),
                    "signal=|s".into(),
                ],
            )
            .unwrap(),
            names: vec!["-r".into(), "--regexp".into()],
            signal_word: true,
            long_only: true,
            no_operand: false,
            targets: Vec::new(),
        };
        let given = |s: &str| w.given(&s.split(' ').map(String::from).collect::<Vec<_>>());
        for yes in ["-regexp x", "-reg x", "-XFSZ -r x", "-Ir x", "-verbose x"] {
            assert!(given(yes), "{yes}");
        }
        for no in ["x", "-s r x", "-I x"] {
            assert!(!given(no), "{no}");
        }
    }

    #[test]
    fn when_option_needs_its_table() {
        let toml = "[pack]\nid = \"t\"\n[[deny]]\npattern = \"x\"\nreason = \"r\"\nwhen_option = [\"-f\"]\n[[deny]]\npattern = \"y\"\nreason = \"r\"\nwhen_option = [\"f\"]\ncommand_options = \"f\"\n[[deny]]\npattern = \"z\"\nreason = \"r\"\nwhen_option = [\"-f\"]\ncommand_options = \"f\"\n";
        let mut w = Vec::new();
        let p = load_pack_str("<t>", toml, &mut w).unwrap();
        assert_eq!(p.deny.len(), 1);
        assert_eq!(w.len(), 2, "{w:?}");
    }

    #[test]
    fn rule_ids_are_kept_and_bad_ones_dropped() {
        let toml = "[pack]\nid = \"t\"\n[[deny]]\nid = \"a-1\"\npattern = \"x\"\nreason = \"r\"\n[[deny]]\nid = \"Bad Id\"\npattern = \"y\"\nreason = \"r\"\n[[deny]]\nid = \"a-1\"\npattern = \"z\"\nreason = \"r\"\n[[deny]]\npattern = \"w\"\nreason = \"r\"\n";
        let mut w = Vec::new();
        let p = load_pack_str("<t>", toml, &mut w).unwrap();
        // The rules stay (dropping one would fail open); only the ids go.
        let ids: Vec<_> = p.deny.iter().map(|r| r.id.as_deref()).collect();
        assert_eq!(ids, [Some("a-1"), None, None, None]);
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(valid_rule_id("force-push") && valid_rule_id("x9"));
        for bad in ["", "-x", "A", "a_b", "a/b", &"a".repeat(65)] {
            assert!(!valid_rule_id(bad), "{bad}");
        }
    }

    #[test]
    fn spec_ask_rules_have_ids() {
        let (packs, _) = crate::builtins::builtin_packs();
        let has = |pack: &str, id: &str| {
            packs
                .iter()
                .filter(|p| p.id == pack)
                .flat_map(|p| p.deny_rules())
                .any(|r| r.id.as_deref() == Some(id))
        };
        assert!(has("core.git", "force-push"));
        assert!(has("db.postgres", "drop-database"));
        assert!(has("container.k8s", "delete-namespace"));
        let engine = crate::engine::Engine::new(packs.clone());
        match engine.evaluate("git push --force origin main") {
            crate::engine::Decision::Deny { pack, pattern, .. } => {
                assert_eq!(engine.rule_id(&pack, &pattern), Some("force-push"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn operand_match_needs_its_targets() {
        let toml = "[pack]\nid = \"t\"\n[[deny]]\npattern = \"x\"\nreason = \"r\"\noperand_match = \"glob\"\n[[deny]]\npattern = \"y\"\nreason = \"r\"\n";
        let mut w = Vec::new();
        let p = load_pack_str("<t>", toml, &mut w).unwrap();
        assert_eq!(p.deny.len(), 1);
        assert!(w[0].message.contains("go together"), "{w:?}");
    }

    #[test]
    fn when_no_operand_reads_both_readings_of_a_signal_word() {
        let w = WhenOption {
            spec: OwnedSpec::parse(
                "cefhimnoxAHLQVg:p:q:r:s:t:u:F:G:O:P:U:",
                &["newest|n".into(), "euid=|u".into(), "signal=".into()],
            )
            .unwrap(),
            names: vec!["-n".into(), "--newest".into(), "-u".into(), "-t".into()],
            signal_word: true,
            long_only: false,
            no_operand: true,
            targets: Vec::new(),
        };
        let m = |s: &str| w.matches(&s.split(' ').map(String::from).collect::<Vec<_>>());
        for yes in [
            "-n",
            "--new",
            "-9 -n",
            "-n -9",
            "-u me",
            "-ume",
            "-n --",
            "--signal KILL -n",
            // `-ttin`: SIGTTIN (no selector), or `-t tin` (a selector).
            "-ttin",
            "--zz",
            // Final review S14: the leading word in lower case too
            // (`-term`: `-t erm`). pkill without a pattern refuses to run
            // anyway.
            "-TERM",
        ] {
            assert!(m(yes), "{yes}");
        }
        for no in ["-n x", "x -n", "-u me x", "-n -- x", "-HUP x", "-9", "-F f"] {
            assert!(!m(no), "{no}");
        }
    }

    #[test]
    fn when_no_operand_skips_a_long_only_value() {
        let w = WhenOption {
            spec: OwnedSpec::parse(
                "eIgy:o:ilqrs:u:vVwn:Z:",
                &["user=|u".into(), "list|l".into()],
            )
            .unwrap(),
            names: vec!["-u".into(), "--user".into()],
            signal_word: true,
            long_only: true,
            no_operand: true,
            targets: Vec::new(),
        };
        let m = |s: &str| w.matches(&s.split(' ').map(String::from).collect::<Vec<_>>());
        for yes in ["-u me", "-user me", "--user=me", "-9 -u me"] {
            assert!(m(yes), "{yes}");
        }
        for no in ["-u me x", "-user me x", "-l", "x"] {
            assert!(!m(no), "{no}");
        }
    }

    #[test]
    fn operand_match_share_min_len_and_substitution() {
        let om = OperandMatch {
            syntax: OperandSyntax::Regex,
            targets: vec![
                "ab".into(),
                "Zc".into(),
                "0d".into(),
                " e".into(),
                "f".into(),
            ],
            need: 4,
            min_len: 2,
            substitution: true,
        };
        let spent = Cell::new(Duration::ZERO);
        let hit = |ops: &[&str]| {
            let ops: Vec<String> = ops.iter().map(|s| s.to_string()).collect();
            om.hits(&ops, &|| false, &spent)
        };
        for yes in [
            &["."][..],
            &[""],
            &["e"],
            &[".*"],
            &["^"],
            &["x", "."],
            &["a("],
            &["[a-z0 ]"],
            &["$(cat f)"],
            &["`cat f`"],
            &["--", "-*."],
            &["-n", "--", "-*."],
        ] {
            assert_eq!(hit(yes), Hit::Yes, "{yes:?}");
        }
        for no in [&["ab"][..], &["[a-c]"], &["node"], &["-f"], &["-*."], &[]] {
            assert_eq!(hit(no), Hit::No, "{no:?}");
        }
    }

    /// Security review: Rust regex class set operations mean nothing to
    /// ERE or fnmatch; such a pattern counts as a match, in both syntaxes.
    #[test]
    fn class_set_operations_count_as_a_match() {
        let hit = |syntax, o: &str| {
            OperandMatch {
                syntax,
                targets: vec!["nginx".into()],
                need: 1,
                min_len: 0,
                substitution: false,
            }
            .hits_within(&[o.to_string()], &|| false, &Cell::default(), Duration::MAX)
        };
        for o in ["[a-z&&[^x]]", "[a-z--x]y", "[a~~b]", "x[[a]&&[b]]"] {
            assert_eq!(hit(OperandSyntax::Regex, o), Hit::Yes, "{o}");
            assert_eq!(hit(OperandSyntax::Glob, o), Hit::Yes, "{o}");
        }
        assert_eq!(hit(OperandSyntax::Regex, "[a-c]x"), Hit::No);
        // Read loosely (after any `[`): fails closed.
        assert_eq!(hit(OperandSyntax::Regex, "[a-c]&&x"), Hit::Yes);
        // `&` and `~` in a glob class are literal characters.
        assert_eq!(glob_regex("[&~]x"), "^[\\&\\~]x$");
        assert!(regex::Regex::new(&glob_regex("[&~a]*")).is_ok());
        assert!(regex::Regex::new(&glob_regex("[&&a]*")).is_ok());
        assert_eq!(hit(OperandSyntax::Glob, "ngin[&x]"), Hit::Yes);
    }

    #[test]
    fn any_expansion_counts() {
        for yes in [
            "$X",
            "${X}",
            "x$X",
            "sa${X}fed",
            "${X}node",
            "a$1",
            "$@",
            "$$x",
            "x$$",
        ] {
            assert!(has_expansion(yes), "{yes}");
        }
        for no in ["node", "$$", "$#", "$?", "$!", "$(x)", "x$", "$"] {
            assert!(!has_expansion(no), "{no}");
        }
    }

    #[test]
    fn target_values() {
        for yes in ["1234", "$$", "2", "1234,5678", "$$,99"] {
            assert!(names_target(yes), "{yes}");
        }
        for no in [
            "",
            "0",
            "1",
            "01",
            "1234,1",
            "$PID",
            "pts/3",
            "12a",
            "99999999999",
        ] {
            assert!(!names_target(no), "{no}");
        }
    }

    #[test]
    fn operand_args_skip_option_values() {
        let w = WhenOption {
            spec: OwnedSpec::parse(
                "cefhimnoxAHLQVg:p:q:r:s:t:u:F:G:O:P:U:",
                &["signal=".into(), "euid=|u".into(), "full|f".into()],
            )
            .unwrap(),
            names: Vec::new(),
            signal_word: true,
            long_only: false,
            no_operand: false,
            targets: Vec::new(),
        };
        let ops = |s: &str| w.operand_args(&s.split(' ').map(String::from).collect::<Vec<_>>());
        assert_eq!(ops("--signal 9 node"), ["--", "node"]);
        assert_eq!(ops("-u 0 node"), ["--", "node"]);
        assert_eq!(ops("-9 -f x -- -y"), ["--", "x", "-y"]);
        // An unknown long option does not swallow the next word.
        assert_eq!(ops("--zz node"), ["--", "node"]);
        // A substitution stays an operand wherever it stands.
        assert_eq!(ops("-u $(id) node"), ["--", "node", "$(id)"]);
    }

    #[test]
    fn new_operand_keys_need_their_partners() {
        let toml = "[pack]\nid = \"t\"\n[[deny]]\npattern = \"x\"\nreason = \"r\"\noperand_match_share = 0.5\n[[deny]]\npattern = \"y\"\nreason = \"r\"\nwhen_no_operand = true\n[[deny]]\npattern = \"z\"\nreason = \"r\"\nwhen_no_operand = true\ncommand_options = \"n\"\n[[deny]]\npattern = \"v\"\nreason = \"r\"\noperand_match = \"regex\"\noperand_targets = [\"a\"]\noperand_match_share = 1.5\n[[deny]]\npattern = \"u\"\nreason = \"r\"\noperand_min_len = 2\n[[deny]]\npattern = \"w\"\nreason = \"r\"\nwhen_no_operand = true\nwhen_option = [\"-n\"]\ncommand_options = \"n\"\n";
        let mut w = Vec::new();
        let p = load_pack_str("<t>", toml, &mut w).unwrap();
        assert_eq!(p.deny.len(), 1, "{w:?}");
        assert_eq!(w.len(), 5, "{w:?}");
    }

    const VALID: &str = r#"
[pack]
id = "test.sample"
name = "Sample"
triggers = ["git"]

[[allow]]
pattern = '^git\s+reset\s+--hard\s+HEAD\b'
reason = "reset to HEAD is fine"

[[deny]]
pattern = '^git\s+reset\s+--hard\b'
reason = "discards uncommitted work"
"#;

    #[test]
    fn loads_valid_pack() {
        let mut w = Vec::new();
        let p = load_pack_str("<t>", VALID, &mut w).expect("loads");
        assert_eq!(p.id, "test.sample");
        assert_eq!(p.allow.len(), 1);
        assert_eq!(p.deny.len(), 1);
        assert!(p.default_on); // defaulted
        assert_eq!(p.version, 1); // defaulted
        assert!(w.is_empty());
    }

    #[test]
    fn deny_without_reason_is_error() {
        let toml = r#"
[pack]
id = "t"
[[deny]]
pattern = 'x'
"#;
        let mut w = Vec::new();
        let err = load_pack_str("<t>", toml, &mut w).unwrap_err();
        assert!(matches!(err, PackError::MissingReason(_)));
    }

    #[test]
    fn uncompilable_regex_drops_rule_with_warning() {
        let toml = r#"
[pack]
id = "t"
[[deny]]
pattern = '('
reason = "bad"
[[deny]]
pattern = 'ok'
reason = "good"
"#;
        let mut w = Vec::new();
        let p = load_pack_str("<t>", toml, &mut w).expect("still loads");
        assert_eq!(p.deny.len(), 1); // the bad one dropped
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn loads_path_rules() {
        let toml = r#"
[pack]
id = "t.paths"

[[deny_path]]
glob = "**/.env"
access = "read"
reason = "secrets"

[[allow_path]]
glob = "**/.env.example"

[[deny_path]]
glob = "relative/path"
reason = "bad glob: dropped with a warning"
"#;
        let mut w = Vec::new();
        let p = load_pack_str("<t>", toml, &mut w).expect("loads");
        assert_eq!(
            p.deny_path,
            vec![PathRule {
                glob: "**/.env".into(),
                access: RuleAccess::Read,
                reason: "secrets".into(),
                ancestors: false,
            }]
        );
        assert_eq!(p.allow_path[0].access, RuleAccess::Any);
        assert_eq!(p.rule_count(), 2);
        assert_eq!(w.len(), 1);
        assert!(w[0].message.contains("relative/path"), "{w:?}");
    }

    #[test]
    fn path_rule_errors() {
        let no_reason = "[pack]\nid = \"t\"\n[[deny_path]]\nglob = \"/x\"\n";
        let mut w = Vec::new();
        assert!(matches!(
            load_pack_str("<t>", no_reason, &mut w),
            Err(PackError::MissingReason(_))
        ));
        let bad_access =
            "[pack]\nid = \"t\"\n[[deny_path]]\nglob = \"/x\"\naccess = \"exec\"\nreason = \"r\"\n";
        assert!(matches!(
            load_pack_str("<t>", bad_access, &mut w),
            Err(PackError::Toml(_))
        ));
    }

    #[test]
    fn unknown_key_in_a_rule_fails_the_load() {
        for table in ["deny", "allow"] {
            let toml = format!(
                "[pack]\nid = \"t\"\n[[{table}]]\npattern = \"x\"\nreason = \"r\"\nwhole_comand = true\n"
            );
            let mut w = Vec::new();
            assert!(
                matches!(load_pack_str("<t>", &toml, &mut w), Err(PackError::Toml(_))),
                "{table}"
            );
        }
        let ok = "[pack]\nid = \"t\"\n[[deny]]\npattern = \"x\"\nreason = \"r\"\nwhole_segment = true\nafter_env_change = true\npeeled_wrappers = true\n";
        let mut w = Vec::new();
        let p = load_pack_str("<t>", ok, &mut w).expect("known keys load");
        assert!(p.deny[0].whole_segment && p.deny[0].after_env_change);
        assert!(p.deny[0].peeled_wrappers);
    }

    #[test]
    fn unknown_key_in_a_path_rule_fails_the_load() {
        for table in ["deny_path", "allow_path"] {
            let toml = format!(
                "[pack]\nid = \"t\"\n[[{table}]]\nglob = \"/x\"\nreason = \"r\"\nacess = \"read\"\n"
            );
            let mut w = Vec::new();
            assert!(
                matches!(load_pack_str("<t>", &toml, &mut w), Err(PackError::Toml(_))),
                "{table}"
            );
        }
    }

    #[test]
    fn ancestors_flag_loads_only_on_variable_rooted_literal_write_globs() {
        let ok = "[pack]\nid = \"t\"\n[[deny_path]]\nglob = \"$SAIIFE_DATA_DIR\"\naccess = \"write\"\nancestors = true\nreason = \"r\"\n";
        let mut w = Vec::new();
        let p = load_pack_str("<t>", ok, &mut w).expect("loads");
        assert!(w.is_empty(), "{w:?}");
        assert!(p.deny_path[0].ancestors);
        for bad in [
            "glob = \"/etc/x\"\naccess = \"write\"",
            "glob = \"**/.env\"\naccess = \"write\"",
            "glob = \"$SAIIFE_DATA_DIR/*\"\naccess = \"write\"",
            "glob = \"$SAIIFE_DATA_DIR/**\"\naccess = \"write\"",
            "glob = \"$SAIIFE_DATA_DIR\"\naccess = \"read\"",
            "glob = \"$SAIIFE_DATA_DIR\"",
        ] {
            let t = format!("[pack]\nid = \"t\"\n[[deny]]\npattern = \"x\"\nreason = \"r\"\n[[deny_path]]\n{bad}\nancestors = true\nreason = \"r\"\n");
            let mut w = Vec::new();
            let p = load_pack_str("<t>", &t, &mut w).expect("pack still loads");
            assert!(p.deny_path.is_empty(), "{bad}");
            assert_eq!(w.len(), 1, "{bad}: {w:?}");
            assert!(w[0].message.contains("ancestors"), "{w:?}");
        }
    }

    #[test]
    fn duplicate_id_in_dir_skips_second() {
        let dir = tempdir();
        std::fs::write(dir.join("a.toml"), VALID).unwrap();
        std::fs::write(dir.join("b.toml"), VALID).unwrap();
        let (packs, warnings) = load_packs_dir(&dir);
        assert_eq!(packs.len(), 1);
        assert!(warnings.iter().any(|w| w.message.contains("duplicate")));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_dir_is_fail_open() {
        let (packs, warnings) = load_packs_dir(Path::new("/no/such/dir/saiifeguard"));
        assert!(packs.is_empty());
        assert_eq!(warnings.len(), 1);
    }

    // Minimal unique temp dir without an external crate.
    fn tempdir() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("saiifeguard-test-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
