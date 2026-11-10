//! Whether a shell glob may match a path a path rule protects, decided from
//! the two patterns alone (`FsView::Lexical`: the service lists no files).
//!
//! The host expands a glob on disk and judges what it finds, so `cat .e*`
//! is denied where a `.env` exists. The lexical view cannot list, and judges
//! the spelling only, which no rule names. Here the glob and each rule's
//! glob are intersected: [`witness`] builds one path both match, if there is
//! one, and the engine judges that path with every rule (an `allow_path`
//! carve-out included). So a glob is denied only when some path it could
//! expand to would be denied, never because of its spelling.
//!
//! The glob is read as the guard's own expansion reads it (`canon::walk`):
//! `*`, `?` and `[…]` within one component, `**` as a whole component for any
//! number of directories, and a leading `.` matched only by a literal `.`. A
//! rule glob has `*`, `?` and `**` (`pathrule`); its other characters are
//! literal.
//!
//! Two readings are less strict than the expansion, on purpose, so honest
//! calls stay allowed (a lexical deny blocks the call in locked mode):
//!
//! - PowerShell's and cmd's wildcards match a leading `.` (`dots`). `?` and
//!   `[…]` do here too, and a `*` does where the rule spells out the rest of
//!   the path (`*env` may be `.env`, `*\credentials` may be
//!   `.aws\credentials`), but not where the rule leaves it open (`.env.*`,
//!   `.ssh/id_*`), or every `*.md` there could be a `.env.md` and every
//!   `src\**\*.ts` a `src\.ssh\id_x.ts`. So `Get-Content *.local` (which may
//!   be `.env.local`) and `Get-Content $HOME\*\id_rsa` are the hook's to
//!   deny, as a symlink is (A21). Nor does a bare `*` or `**` that ends the
//!   glob ("everything here"): `rm -rf *` in a build folder is not denied as
//!   a possible write onto a `.claude` there, and `type *` is not a possible
//!   `.env` read. Bash's `dotglob` is not modelled by the
//!   host's expansion either, so there the two views agree.
//! - A glob's `**` stands for one folder a rule names (as `*` does: bash
//!   without `globstar`, PowerShell and cmd read it so), or for any number of
//!   folders the rule leaves open, but not for several named ones. Otherwise
//!   every `src/**/*.rs` could be `src/AppData/x/Microsoft/Credentials/a.rs`
//!   (`**/AppData/*/Microsoft/Credentials/**`). `~/.aws/**` still meets
//!   `**/.aws/credentials`.
//!
//! One witness can fall into an `allow_path` carve-out while other matches of
//! the glob would not (`.e?v.example*` is `.env.example` with its star empty):
//! the engine then tries more (`filled`, and other characters by `rot`), and
//! passes a rule only when every one is carved out.

/// One element of a component pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum El {
    Lit(char),
    /// `?`: one character.
    One,
    /// `*`: any run of characters.
    Star,
    /// `[…]` / `[!…]` / `[^…]`: inclusive ranges (a single character is a
    /// range of one).
    Class {
        neg: bool,
        ranges: Vec<(char, char)>,
    },
}

/// One path component of a pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Seg {
    /// `**`: any number of components.
    Deep,
    Name(Vec<El>),
}

/// A pattern as the components of an absolute path. On Windows the first
/// component is the drive (`c:`).
pub(crate) type Pattern = Vec<Seg>;

/// The character a wildcard stands for in a witness: not `/`, not `.`, and
/// literal in no built-in rule, so a witness does not fall into an
/// `allow_path` carve-out by chance.
const FILL: char = '#';

/// A shell glob's absolute, lexically normalized text (as `canon::lexical_form`
/// or `winpath::canonical` gives it) as a pattern. `None` when it has no
/// wildcard: there is nothing to expand.
pub(crate) fn shell_pattern(abs: &str, fold: bool) -> Option<Pattern> {
    let text = if fold {
        crate::winpath::fold(abs)
    } else {
        abs.to_string()
    };
    let mut wild = false;
    let mut out = Vec::new();
    for comp in text.split('/').filter(|c| !c.is_empty()) {
        if comp == "**" {
            wild = true;
            out.push(Seg::Deep);
            continue;
        }
        let els = shell_component(comp);
        wild |= els.iter().any(|e| !matches!(e, El::Lit(_)));
        out.push(Seg::Name(els));
    }
    wild.then_some(out)
}

fn shell_component(comp: &str) -> Vec<El> {
    let s: Vec<char> = comp.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            '*' => {
                if out.last() != Some(&El::Star) {
                    out.push(El::Star);
                }
                i += 1;
            }
            '?' => {
                out.push(El::One);
                i += 1;
            }
            '[' => match class(&s[i..]) {
                Some((el, len)) => {
                    out.push(el);
                    i += len;
                }
                None => {
                    out.push(El::Lit('['));
                    i += 1;
                }
            },
            c => {
                out.push(El::Lit(c));
                i += 1;
            }
        }
    }
    out
}

/// A `[…]` class at the start of `p`, read as `canon::class` reads it, and
/// its length; `None` if unterminated (then `[` is literal).
fn class(p: &[char]) -> Option<(El, usize)> {
    let mut i = 1;
    let neg = matches!(p.get(i), Some('!' | '^'));
    if neg {
        i += 1;
    }
    let first = i;
    let mut ranges = Vec::new();
    while i < p.len() {
        if p[i] == ']' && i > first {
            return Some((El::Class { neg, ranges }, i + 1));
        }
        if p.get(i + 1) == Some(&'-') && p.get(i + 2).is_some_and(|e| *e != ']') {
            ranges.push((p[i], p[i + 2]));
            i += 3;
        } else {
            ranges.push((p[i], p[i]));
            i += 1;
        }
    }
    None
}

/// A rule glob with its variable already replaced (`pathrule`): `**` is a
/// whole component, `*` and `?` wildcards, all else literal.
pub(crate) fn rule_pattern(full: &str, fold: bool) -> Pattern {
    let text = if fold {
        crate::winpath::fold(full)
    } else {
        full.to_string()
    };
    text.split('/')
        .filter(|c| !c.is_empty())
        .map(|comp| {
            if comp == "**" {
                return Seg::Deep;
            }
            let mut els: Vec<El> = Vec::new();
            for c in comp.chars() {
                match c {
                    '*' if els.last() == Some(&El::Star) => {}
                    '*' => els.push(El::Star),
                    '?' => els.push(El::One),
                    c => els.push(El::Lit(c)),
                }
            }
            Seg::Name(els)
        })
        .collect()
}

/// `p` with a fill character in front of each `*` of a name: a second
/// witness, whose stars take a character, for when the first one (every star
/// empty) fell into an `allow_path` carve-out (`.e?v.example*` is
/// `.env.example` with its star empty, `.env.example#` without).
pub(crate) fn filled(p: &[Seg]) -> Pattern {
    p.iter()
        .map(|s| match s {
            Seg::Deep => Seg::Deep,
            Seg::Name(els) => Seg::Name(
                els.iter()
                    .flat_map(|e| match e {
                        El::Star => vec![El::Lit(FILL), El::Star],
                        e => vec![e.clone()],
                    })
                    .collect(),
            ),
        })
        .collect()
}

/// One path `glob` (a shell glob) and `rule` (a rule glob) both match, as its
/// components, if there is one. `dots`: the glob's wildcards match a leading
/// `.`. `nocase`: characters compare case-insensitively (the rule regexes
/// are; a folded Windows path is already lower case). `rot` picks another
/// character where several would do (a class's other members), for a further
/// witness when one fell into a carve-out.
pub(crate) fn witness(
    glob: &[Seg],
    rule: &[Seg],
    dots: bool,
    nocase: bool,
    rot: usize,
) -> Option<Vec<String>> {
    // Breadth first over (glob component, rule component), remembering how
    // each state was reached and what component that step produced.
    let (gl, rl) = (glob.len(), rule.len());
    let idx = |g: usize, r: usize| g * (rl + 1) + r;
    let mut seen: Vec<Option<(usize, Option<String>)>> = vec![None; (gl + 1) * (rl + 1)];
    let start = idx(0, 0);
    seen[start] = Some((start, None));
    let mut queue = std::collections::VecDeque::from([(0usize, 0usize)]);
    let star = [El::Star];
    while let Some((g, r)) = queue.pop_front() {
        if g == gl && r == rl {
            let mut comps = Vec::new();
            let mut at = idx(g, r);
            while at != start {
                let (prev, comp) = seen[at].clone().expect("reached");
                comps.extend(comp);
                at = prev;
            }
            comps.reverse();
            return Some(comps);
        }
        let mut next: Vec<(usize, usize, Option<String>)> = Vec::new();
        if glob.get(g) == Some(&Seg::Deep) {
            next.push((g + 1, r, None));
        }
        if rule.get(r) == Some(&Seg::Deep) {
            next.push((g, r + 1, None));
        }
        if let (Some(gs), Some(rs)) = (glob.get(g), rule.get(r)) {
            // With `dots`, a `*` stands for a leading `.` only where the rule
            // spells out the rest of the path (`.env`, `.aws/credentials`).
            // And a bare `*` or `**` that ends the glob ("everything here")
            // stands for none: `rm -rf *` in a build folder is no write onto
            // a `.claude` there.
            let bare_end = g + 1 == gl && bare(gs);
            let star_dot = dots
                && !bare_end
                && rule[r..]
                    .iter()
                    .all(|s| matches!(s, Seg::Name(n) if literal(n)));
            let comp = match (gs, rs) {
                (Seg::Deep, Seg::Deep) => None,
                // The glob's `**` reads as `*` here: it skips hidden names
                // (unless `dots`), and stands for one folder a rule names at
                // most, or any number the rule leaves open (module header).
                (Seg::Deep, Seg::Name(n)) => component(&star, n, dots, star_dot, nocase, rot),
                (Seg::Name(n), Seg::Deep) => component(n, &star, dots, star_dot, nocase, rot),
                (Seg::Name(a), Seg::Name(b)) => component(a, b, dots, star_dot, nocase, rot),
            };
            if let Some(c) = comp {
                let named = matches!(rs, Seg::Name(n) if literal(n));
                let g2 = if *gs == Seg::Deep && !named { g } else { g + 1 };
                let r2 = if *rs == Seg::Deep { r } else { r + 1 };
                next.push((g2, r2, Some(c)));
            }
        }
        for (g2, r2, comp) in next {
            let at = idx(g2, r2);
            if seen[at].is_none() {
                seen[at] = Some((idx(g, r), comp));
                queue.push_back((g2, r2));
            }
        }
    }
    None
}

/// `**`, or a name that is one `*` (or cmd's `*.*`, "every file").
fn bare(s: &Seg) -> bool {
    match s {
        Seg::Deep => true,
        Seg::Name(els) => {
            els.as_slice() == [El::Star] || els.as_slice() == [El::Star, El::Lit('.'), El::Star]
        }
    }
}

fn literal(els: &[El]) -> bool {
    els.iter().all(|e| matches!(e, El::Lit(_)))
}

/// A non-empty name both component patterns match, if any. `glob` is the
/// shell's side: a leading `.` must be its literal first element, or with
/// `dots` any first element, a `*` only with `star_dot` (see the module
/// header).
fn component(
    glob: &[El],
    rule: &[El],
    dots: bool,
    star_dot: bool,
    nocase: bool,
    rot: usize,
) -> Option<String> {
    let dot_ok = match glob.first() {
        Some(El::Lit('.')) => true,
        Some(El::Star) | None => star_dot,
        Some(_) => dots,
    };
    let (gl, rl) = (glob.len(), rule.len());
    // States (glob element, rule element, started); a star stays put when it
    // takes a character.
    let idx = |g: usize, r: usize, s: bool| (g * (rl + 1) + r) * 2 + usize::from(s);
    let mut seen: Vec<Option<(usize, Option<char>)>> = vec![None; (gl + 1) * (rl + 1) * 2];
    let start = idx(0, 0, false);
    seen[start] = Some((start, None));
    let mut queue = std::collections::VecDeque::from([(0usize, 0usize, false)]);
    while let Some((g, r, s)) = queue.pop_front() {
        if g == gl && r == rl && s {
            let mut name = Vec::new();
            let mut at = idx(g, r, s);
            while at != start {
                let (prev, c) = seen[at].expect("reached");
                name.extend(c);
                at = prev;
            }
            name.reverse();
            return Some(name.into_iter().collect());
        }
        let mut next: Vec<(usize, usize, bool, Option<char>)> = Vec::new();
        if glob.get(g) == Some(&El::Star) {
            next.push((g + 1, r, s, None));
        }
        if rule.get(r) == Some(&El::Star) {
            next.push((g, r + 1, s, None));
        }
        if let (Some(a), Some(b)) = (glob.get(g), rule.get(r)) {
            if let Some(c) = common(a, b, !s && !dot_ok, nocase, rot) {
                let g2 = if *a == El::Star { g } else { g + 1 };
                let r2 = if *b == El::Star { r } else { r + 1 };
                next.push((g2, r2, true, Some(c)));
            }
        }
        for (g2, r2, s2, c) in next {
            let at = idx(g2, r2, s2);
            if seen[at].is_none() {
                seen[at] = Some((idx(g, r, s), c));
                queue.push_back((g2, r2, s2));
            }
        }
    }
    None
}

/// A character both elements take (never `/`; never `.` with `no_dot`).
fn common(a: &El, b: &El, no_dot: bool, nocase: bool, rot: usize) -> Option<char> {
    let ok =
        |c: char| c != '/' && !(no_dot && c == '.') && takes(a, c, nocase) && takes(b, c, nocase);
    // A literal on either side is the only candidate; else the first
    // character a class names, or the fill.
    let mut candidates: Vec<char> = Vec::new();
    for e in [a, b] {
        match e {
            El::Lit(c) => return Some(*c).filter(|c| ok(*c)),
            El::Class { neg: false, ranges } => {
                candidates.extend(ranges.iter().flat_map(|(lo, hi)| [*lo, *hi]))
            }
            _ => {}
        }
    }
    candidates.extend([FILL, 'z', '0', '_', '~']);
    let mut fit: Vec<char> = Vec::new();
    for c in candidates {
        if ok(c) && !fit.contains(&c) {
            fit.push(c);
        }
    }
    (!fit.is_empty()).then(|| fit[rot % fit.len()])
}

/// Whether `e` takes the single character `c`.
fn takes(e: &El, c: char, nocase: bool) -> bool {
    let same = |x: char, y: char| x == y || (nocase && x.to_lowercase().eq(y.to_lowercase()));
    match e {
        El::Lit(x) => same(*x, c),
        El::One | El::Star => true,
        El::Class { neg, ranges } => {
            let lower: Vec<char> = if nocase {
                c.to_lowercase().chain(c.to_uppercase()).collect()
            } else {
                vec![c]
            };
            let hit = lower
                .iter()
                .any(|c| ranges.iter().any(|(lo, hi)| lo <= c && c <= hi));
            hit != *neg
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(glob: &str, rule: &str) -> Option<String> {
        let g = shell_pattern(glob, false).expect("a glob");
        witness(&g, &rule_pattern(rule, false), false, false, 0)
            .map(|c| format!("/{}", c.join("/")))
    }

    #[test]
    fn a_glob_and_a_rule_meet_on_one_path() {
        assert_eq!(w("/h/app/.e*", "**/.env").as_deref(), Some("/h/app/.env"));
        assert_eq!(
            w("/h/.ssh/id_*", "**/.ssh/id_*").as_deref(),
            Some("/h/.ssh/id_")
        );
        assert_eq!(
            w("/h/.s?h/id_rsa", "**/.ssh/id_*").as_deref(),
            Some("/h/.ssh/id_rsa")
        );
        assert_eq!(
            w("/h/app/.[e]nv", "**/.env").as_deref(),
            Some("/h/app/.env")
        );
        assert_eq!(
            w("/h/.aws/cred*", "/h/.aws/credentials").as_deref(),
            Some("/h/.aws/credentials")
        );
        assert!(w("/h/app/**/.env*", "**/.env").is_some());
        assert!(w("/proc/*/environ", "/proc/*/environ").is_some());
        assert!(w("/h/app/*/x", "**/.config/gcloud/**").is_none());
        assert!(w("/h/*/gcloud/x", "**/.config/gcloud/**").is_none());
        assert!(w("/h/.*/gcloud/x", "**/.config/gcloud/**").is_some());
    }

    #[test]
    fn wildcards_skip_a_leading_dot() {
        for g in [
            "/h/app/*",
            "/h/app/*env",
            "/h/app/?env",
            "/h/app/[.]env",
            "/h/**/*",
        ] {
            assert_eq!(w(g, "**/.env"), None, "{g}");
        }
        assert_eq!(w("/h/**/x", "**/.ssh/x"), None);
        // PowerShell and cmd: `?` and `[…]` match a leading `.`, and so does
        // `*` for a name the rule spells out (`.env`, `.aws`), not for one it
        // leaves open (`.env.*`; the module header says why).
        let dots = |g: &str, r: &str| {
            let g = shell_pattern(g, false).unwrap();
            witness(&g, &rule_pattern(r, false), true, false, 0).is_some()
        };
        for g in [
            "/h/app/?env",
            "/h/app/[.]env",
            "/h/app/[!x]env",
            "/h/app/*env",
            "/h/app/*v",
        ] {
            assert!(dots(g, "**/.env"), "{g}");
        }
        // A bare `*` or `**` at the end means "everything here".
        assert!(!dots("/h/app/*", "**/.env"));
        assert!(!dots("/h/app/**", "**/.env"));
        assert!(!dots("/h/app/*.*", "**/.claude"));
        assert!(dots("/h/*/credentials", "**/.aws/credentials"));
        assert!(dots("/h/**/credentials", "**/.aws/credentials"));
        assert!(!dots("/h/app/*.md", "**/.env.*"));
        assert!(!dots("/h/app/src/**/*.ts", "**/.ssh/id_*"));
        assert!(!dots("/h/*/id_rsa", "**/.ssh/id_*"));
        assert!(dots("/h/.ssh/*", "**/.ssh/id_*"));
        assert!(!dots("/h/app/*", "**/.env.*"));
        assert!(dots("/h/app/?env.local", "**/.env.*"));
    }

    #[test]
    fn a_double_star_is_at_least_a_star() {
        // Bash without `globstar`, PowerShell and cmd read `**` as `*`.
        assert!(w("/h/.aws/**", "**/.aws/credentials").is_some());
        assert!(w("/h/.aws/**/credentials", "**/.aws/credentials").is_some());
        assert!(w("/proc/**/environ", "/proc/*/environ").is_some());
        assert!(w("/h/.ssh/**", "**/.ssh/id_*").is_some());
        assert_eq!(w("/h/**/credentials", "**/.aws/credentials"), None);
    }

    #[test]
    fn filled_stars_take_a_character() {
        let g = shell_pattern("/h/app/.e?v.example*", false).unwrap();
        let r = rule_pattern("**/.env.*", false);
        let first = witness(&g, &r, false, false, 0).unwrap();
        assert_eq!(first.last().unwrap(), ".env.example");
        let second = witness(&filled(&g), &r, false, false, 0).unwrap();
        assert_eq!(second.last().unwrap(), ".env.example#");
        // Another member of a class.
        let g = shell_pattern("/h/.ssh/id_rsa.pu[bx]", false).unwrap();
        let r = rule_pattern("**/.ssh/id_*", false);
        assert_eq!(witness(&g, &r, false, false, 0).unwrap()[2], "id_rsa.pub");
        assert_eq!(witness(&g, &r, false, false, 1).unwrap()[2], "id_rsa.pux");
    }

    #[test]
    fn a_double_star_stands_for_no_named_folder() {
        let creds = "**/AppData/*/Microsoft/Credentials/**";
        assert_eq!(w("/h/app/src/**/*.rs", creds), None);
        assert_eq!(w("/h/**/Credentials/x", creds), None);
        assert_eq!(w("/**", "/proc/*/environ"), None);
        assert!(w("/h/AppData/Roaming/Microsoft/*/x", creds).is_some());
        assert!(w("/h/AppData/**/Microsoft/Credentials/x", creds).is_some());
        assert!(w("/proc/**/environ", "/proc/*/environ").is_some());
    }

    #[test]
    fn disjoint_names_never_meet() {
        for (g, r) in [
            ("/h/app/*.rs", "**/.env"),
            ("/h/app/src/*.md", "**/.env.*"),
            ("/h/app/target/*.o", "**/.ssh/id_*"),
            ("/h/app/docs/*", "**/.npmrc"),
            ("/h/.ssh/*.pub", "/h/.aws/credentials"),
            ("/h/app/[!.]env", "**/.env"),
            ("/h/app/.e[!n]v", "**/.env"),
        ] {
            assert_eq!(w(g, r), None, "{g} vs {r}");
        }
    }

    #[test]
    fn case_folds_when_asked() {
        let g = shell_pattern("/h/app/.E*", false).unwrap();
        let r = rule_pattern("**/.env", false);
        assert!(witness(&g, &r, false, false, 0).is_none());
        assert!(witness(&g, &r, false, true, 0).is_some());
        let g = shell_pattern("c:/Users/a/.SSH/id_*", true).unwrap();
        assert!(witness(&g, &rule_pattern("**/.ssh/id_*", true), true, false, 0).is_some());
    }

    #[test]
    fn plain_words_are_no_glob() {
        assert!(shell_pattern("/h/app/.env", false).is_none());
        assert!(shell_pattern("/h/app/[x", false).is_none());
    }
}
