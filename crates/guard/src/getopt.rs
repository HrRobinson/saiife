//! GNU `getopt_long`, as far as the guard needs it: which words of a
//! command line are options, which option each one is, and which word is
//! its value.
//!
//! Every reader of a command's options goes through here, so they all agree
//! with the tool: wrapper peeling, the files a wrapper reads, `env -S`, and
//! the `when_option` of pack rules (`pkill -f`). That includes the long
//! option prefixes getopt accepts (`--arg-f` is `--arg-file`, `--f` is
//! `--full` for pkill) and short option bundles (`-0a FILE`, `-9f`).

/// Whether an option takes a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arg {
    /// A flag.
    No,
    /// `--name VALUE`, `--name=VALUE`, `-xVALUE`, `-x VALUE`.
    Required,
    /// Only attached: `--name=VALUE`, `-xVALUE`.
    Optional,
}

/// One long option of a tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongOpt<'a> {
    pub name: &'a str,
    pub arg: Arg,
    /// The short option it is an alias of; `'\0'` for none. glibc treats
    /// two prefix matches with the same alias and arity as one option
    /// (`flock --n…`: `--nb`, `--nonblocking`), not as ambiguous.
    pub short: char,
}

/// A flag long option (`short` may be `'\0'`).
pub const fn flag(name: &str, short: char) -> LongOpt<'_> {
    LongOpt {
        name,
        arg: Arg::No,
        short,
    }
}

/// A long option with a required value.
pub const fn req(name: &str, short: char) -> LongOpt<'_> {
    LongOpt {
        name,
        arg: Arg::Required,
        short,
    }
}

/// A long option with an optional (attached only) value.
pub const fn opt(name: &str, short: char) -> LongOpt<'_> {
    LongOpt {
        name,
        arg: Arg::Optional,
        short,
    }
}

/// A tool's options: a getopt optstring (`"+a:bc::"`) and its long options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spec<'a> {
    pub short: &'a str,
    pub long: &'a [LongOpt<'a>],
}

/// What a long option name resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolved<'a> {
    Known(&'a LongOpt<'a>),
    /// No option has this name or prefix; the tool refuses it.
    Unknown,
    /// A prefix of two different options; the tool refuses it.
    Ambiguous,
}

/// One option (of an option word) of a command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opt<'a, 'w> {
    Known {
        /// The short letter (given, or the long option's alias; `'\0'`).
        short: char,
        /// The long option's full name, when given in long form.
        long: Option<&'a str>,
        value: Option<&'w str>,
        /// Index of the option's word, and whether the value is the next
        /// word rather than attached.
        word: usize,
        separate: bool,
    },
    /// A long option the tool does not know, or an ambiguous prefix: the
    /// text after `--`, up to any `=`.
    Unknown { name: &'w str },
}

impl<'a> Spec<'a> {
    pub const fn new(short: &'a str, long: &'a [LongOpt<'a>]) -> Self {
        Spec { short, long }
    }

    /// glibc `getopt_long`'s lookup: an exact name, else the one option
    /// `name` is a prefix of.
    pub fn resolve_long(&self, name: &str) -> Resolved<'a> {
        if name.is_empty() {
            return Resolved::Unknown;
        }
        let long: &'a [LongOpt<'a>] = self.long;
        if let Some(exact) = long.iter().find(|o| o.name == name) {
            return Resolved::Known(exact);
        }
        let mut found: Option<&'a LongOpt<'a>> = None;
        for o in long.iter().filter(|o| o.name.starts_with(name)) {
            match found {
                None => found = Some(o),
                Some(f) if f.arg == o.arg && f.short == o.short && f.short != '\0' => {}
                Some(_) => return Resolved::Ambiguous,
            }
        }
        found.map_or(Resolved::Unknown, Resolved::Known)
    }

    /// The arity of short option `c`; `None` when the optstring lacks it.
    pub fn short_arg(&self, c: char) -> Option<Arg> {
        if matches!(c, ':' | '+' | '-') {
            return None;
        }
        let pos = self.short.find(c)?;
        let rest = &self.short[pos + c.len_utf8()..];
        Some(if rest.starts_with("::") {
            Arg::Optional
        } else if rest.starts_with(':') {
            Arg::Required
        } else {
            Arg::No
        })
    }

    /// Is `name` (unknown or ambiguous) a prefix of an option that takes
    /// the next word? Peeling then skips that word too: the tool refuses
    /// the option, and a newer one may take a value.
    fn prefix_of_required(&self, name: &str) -> bool {
        !name.is_empty()
            && self
                .long
                .iter()
                .any(|o| o.arg == Arg::Required && o.name.starts_with(name))
    }

    /// If `args[i]` is an option word, tell `visit` about each option in
    /// it and return the index after it and its value; `None` when it is
    /// not an option (an operand, `-`, or `--`, which the caller handles).
    pub fn option_at<'w, W: AsRef<str>>(
        &self,
        args: &'w [W],
        i: usize,
        visit: &mut dyn FnMut(Opt<'a, 'w>),
    ) -> Option<usize> {
        let tok = args.get(i)?.as_ref();
        if tok == "--" || tok == "-" || !tok.starts_with('-') {
            return None;
        }
        if let Some(long) = tok.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (long, None),
            };
            return Some(match self.resolve_long(name) {
                Resolved::Known(o) => {
                    let separate = o.arg == Arg::Required && attached.is_none();
                    let value = if separate {
                        args.get(i + 1).map(AsRef::as_ref)
                    } else {
                        attached
                    };
                    visit(Opt::Known {
                        short: o.short,
                        long: Some(o.name),
                        value,
                        word: i,
                        separate,
                    });
                    if separate {
                        i + 2
                    } else {
                        i + 1
                    }
                }
                Resolved::Unknown | Resolved::Ambiguous => {
                    visit(Opt::Unknown { name });
                    if attached.is_none() && self.prefix_of_required(name) {
                        i + 2
                    } else {
                        i + 1
                    }
                }
            });
        }
        let bundle = &tok[1..];
        for (pos, c) in bundle.char_indices() {
            let after = &bundle[pos + c.len_utf8()..];
            match self.short_arg(c) {
                Some(Arg::Required) => {
                    let separate = after.is_empty();
                    let value = if separate {
                        args.get(i + 1).map(AsRef::as_ref)
                    } else {
                        Some(after)
                    };
                    visit(Opt::Known {
                        short: c,
                        long: None,
                        value,
                        word: i,
                        separate,
                    });
                    return Some(if separate { i + 2 } else { i + 1 });
                }
                Some(Arg::Optional) => {
                    visit(Opt::Known {
                        short: c,
                        long: None,
                        value: (!after.is_empty()).then_some(after),
                        word: i,
                        separate: false,
                    });
                    return Some(i + 1);
                }
                // A flag, or a letter the tool does not know (it refuses
                // it): read on through the bundle.
                Some(Arg::No) | None => visit(Opt::Known {
                    short: c,
                    long: None,
                    value: None,
                    word: i,
                    separate: false,
                }),
            }
        }
        Some(i + 1)
    }

    /// Walk the leading options of `args` (getopt with a `+` optstring:
    /// options stop at the first operand; `--` ends them and is skipped).
    /// Returns the index of the first operand.
    pub fn leading<'w, W: AsRef<str>>(
        &self,
        args: &'w [W],
        visit: &mut dyn FnMut(Opt<'a, 'w>),
    ) -> usize {
        let mut i = 0;
        while i < args.len() {
            match self.option_at(args, i, visit) {
                Some(next) => i = next,
                None if args[i].as_ref() == "--" => return i + 1,
                None => return i,
            }
        }
        args.len()
    }

    /// Walk every option of `args`, operands in between included (GNU
    /// getopt's argument permutation), up to a `--`.
    pub fn all<'w, W: AsRef<str>>(&self, args: &'w [W], visit: &mut dyn FnMut(Opt<'a, 'w>)) {
        let mut i = 0;
        while i < args.len() {
            match self.option_at(args, i, visit) {
                Some(next) => i = next,
                None if args[i].as_ref() == "--" => return,
                None => i += 1,
            }
        }
    }
}

/// A tool's options as a pack writes them (`command_options`,
/// `command_long_options`), owned; `with` lends a `Spec` of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedSpec {
    short: String,
    long: Vec<(String, Arg, char)>,
}

impl OwnedSpec {
    /// Parse a pack's options: a getopt optstring, and long options written
    /// `name` (flag), `name=` (value), `name[=]` (optional value), each
    /// with an optional `|c` short alias.
    pub fn parse(short: &str, entries: &[String]) -> Result<Self, String> {
        let long = entries
            .iter()
            .map(|e| {
                let (spec, short) = match e.split_once('|') {
                    Some((s, c)) => {
                        let mut chars = c.chars();
                        match (chars.next(), chars.next()) {
                            (Some(ch), None) => (s, ch),
                            _ => return Err(format!("bad short alias in {e:?}")),
                        }
                    }
                    None => (e.as_str(), '\0'),
                };
                let (name, arg) = if let Some(n) = spec.strip_suffix("[=]") {
                    (n, Arg::Optional)
                } else if let Some(n) = spec.strip_suffix('=') {
                    (n, Arg::Required)
                } else {
                    (spec, Arg::No)
                };
                if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                    return Err(format!("bad long option {e:?}"));
                }
                Ok((name.to_string(), arg, short))
            })
            .collect::<Result<_, _>>()?;
        Ok(OwnedSpec {
            short: short.to_string(),
            long,
        })
    }

    /// Run `f` with the options as a `Spec`.
    pub fn with<R>(&self, f: impl FnOnce(&Spec<'_>) -> R) -> R {
        let long: Vec<LongOpt<'_>> = self
            .long
            .iter()
            .map(|(name, arg, short)| LongOpt {
                name,
                arg: *arg,
                short: *short,
            })
            .collect();
        f(&Spec::new(&self.short, &long))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: Spec<'static> = Spec::new(
        "+a:bc::",
        &[
            req("arg-file", 'a'),
            flag("bell", 'b'),
            opt("color", 'c'),
            flag("nb", 'n'),
            flag("nonblocking", 'n'),
            flag("no-fork", 'F'),
            req("wait", 'w'),
            req("timeout", 'w'),
        ],
    );

    fn known(r: Resolved<'static>) -> Option<&'static str> {
        match r {
            Resolved::Known(o) => Some(o.name),
            _ => None,
        }
    }

    #[test]
    fn long_prefixes_resolve_like_glibc() {
        assert_eq!(known(T.resolve_long("arg-f")), Some("arg-file"));
        assert_eq!(known(T.resolve_long("a")), Some("arg-file"));
        assert_eq!(known(T.resolve_long("nb")), Some("nb"), "exact wins");
        assert_eq!(known(T.resolve_long("non")), Some("nonblocking"));
        assert_eq!(
            T.resolve_long("n"),
            Resolved::Ambiguous,
            "nb/no-fork differ"
        );
        assert_eq!(T.resolve_long("x"), Resolved::Unknown);
        assert_eq!(T.resolve_long(""), Resolved::Unknown);
    }

    #[test]
    fn values_and_bundles() {
        let args = [
            "-ba", "F", "--arg", "G", "--color", "-cX", "--wai", "5", "cmd",
        ];
        let mut seen = Vec::new();
        let first = T.leading(&args, &mut |o| {
            if let Opt::Known { short, value, .. } = o {
                seen.push((short, value.map(str::to_string)));
            }
        });
        assert_eq!(args[first], "cmd");
        assert_eq!(
            seen,
            vec![
                ('b', None),
                ('a', Some("F".into())),
                ('a', Some("G".into())),
                ('c', None),
                ('c', Some("X".into())),
                ('w', Some("5".into())),
            ]
        );
    }

    #[test]
    fn unknown_long_is_reported_and_skips_like_a_value_option() {
        let args = ["--ti", "5", "--zz", "--wa", "6", "cmd"];
        let mut unknown = Vec::new();
        let first = T.leading(&args, &mut |o| {
            if let Opt::Unknown { name } = o {
                unknown.push(name.to_string());
            }
        });
        assert_eq!(args[first], "cmd");
        assert_eq!(unknown, vec!["zz"]);
    }

    #[test]
    fn permutation_sees_options_after_operands() {
        let args = ["pat", "-b", "--", "-a"];
        let mut shorts = Vec::new();
        T.all(&args, &mut |o| {
            if let Opt::Known { short, .. } = o {
                shorts.push(short);
            }
        });
        assert_eq!(shorts, vec!['b']);
    }

    #[test]
    fn parses_pack_option_lists() {
        let o =
            OwnedSpec::parse("f", &["full|f".into(), "signal=".into(), "eof[=]|e".into()]).unwrap();
        o.with(|s| {
            assert_eq!(s.long[0], flag("full", 'f'));
            assert_eq!(s.long[1], req("signal", '\0'));
            assert_eq!(s.long[2], opt("eof", 'e'));
            assert_eq!(s.short_arg('f'), Some(Arg::No));
        });
        assert!(OwnedSpec::parse("", &["a|bc".into()]).is_err());
        assert!(OwnedSpec::parse("", &["=".into()]).is_err());
    }
}
