//! Where a `cd` earlier in a command line leaves the shell, for the regex
//! rules of `core.filesystem`: `cd / && rm -rf *` is judged as
//! `rm -rf /*`.
//!
//! Purely lexical (no filesystem access, so it stays inside the latency
//! budget): `..` pops a component, a symlink is not followed. A target that
//! cannot be resolved this way (`cd -`, `cd "$(…)"`, `cd $DIR`, `~user`,
//! `popd`) makes the directory unknown, and an unknown directory rewrites
//! nothing: the command is judged as written, as before.
//!
//! The path-rule phases keep their own record (`ShellState::cwds`), which
//! resolves symlinks and keeps every directory the shell may be in.

use std::path::{Component, Path};

use crate::lexer::Word;

/// A directory spelled lexically: from `/`, or from the home directory
/// (`~`), so the rules' `~` / `$HOME` targets match it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Dir {
    home: bool,
    parts: Vec<String>,
}

impl Dir {
    fn root() -> Dir {
        Dir {
            home: false,
            parts: Vec::new(),
        }
    }

    fn home() -> Dir {
        Dir {
            home: true,
            parts: Vec::new(),
        }
    }

    fn from_path(path: &Path) -> Option<Dir> {
        if !path.is_absolute() {
            return None;
        }
        let mut dir = Dir::root();
        for c in path.components() {
            match c {
                Component::Normal(s) => dir.parts.push(s.to_str()?.to_string()),
                Component::ParentDir => {
                    dir.parts.pop();
                }
                _ => {}
            }
        }
        Some(dir)
    }

    /// `rel` (a relative path) joined onto this directory. `None` when a
    /// `..` climbs above a home directory whose location is unknown.
    fn join(&self, rel: &str, home: Option<&Path>) -> Option<Dir> {
        let mut dir = self.clone();
        for part in rel.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    if dir.parts.pop().is_none() && dir.home {
                        dir = Dir::from_path(home?)?;
                        dir.parts.pop();
                    }
                }
                p => dir.parts.push(p.to_string()),
            }
        }
        Some(dir)
    }

    /// The directory as the rules spell it: `/`, `/usr/*`, `~`, `~/x`. A
    /// path inside the home directory is spelled from `~`.
    fn render(&self, home: Option<&Path>) -> String {
        let mut dir = self.clone();
        if !dir.home {
            if let Some(h) = home.and_then(Dir::from_path) {
                if !h.parts.is_empty() && dir.parts.starts_with(&h.parts) {
                    dir.parts.drain(..h.parts.len());
                    dir.home = true;
                }
            }
        }
        match (dir.home, dir.parts.is_empty()) {
            (true, true) => "~".to_string(),
            (true, false) => format!("~/{}", dir.parts.join("/")),
            (false, _) => format!("/{}", dir.parts.join("/")),
        }
    }
}

/// The working directory for the regex rules over the rest of a command
/// line (`ShellState`).
#[derive(Clone, Debug)]
pub(crate) struct RuleCwd {
    /// Where the shell is; `None` when unknown.
    dir: Option<Dir>,
    /// A `cd` ran earlier on the line: only then are operands rewritten
    /// (a line without one is judged exactly as before).
    moved: bool,
}

impl RuleCwd {
    /// The directory the command line starts in (the agent's), if known.
    pub(crate) fn start(cwd: Option<&Path>) -> RuleCwd {
        RuleCwd {
            dir: cwd.and_then(Dir::from_path),
            moved: false,
        }
    }

    /// A `cd`/`pushd`/`popd` segment (`argv` normalized, `words` the
    /// resolved words in the same positions) ran; any other command is
    /// ignored.
    pub(crate) fn command(&mut self, argv: &[String], words: &[Word], home: Option<&Path>) {
        let cmd = argv.first().map(String::as_str);
        let pushd = match cmd {
            Some("cd") => false,
            Some("pushd") => true,
            Some("popd") => {
                self.moved = true;
                self.dir = None;
                return;
            }
            _ => return,
        };
        self.moved = true;
        self.dir = self.target(argv, words, pushd, home);
    }

    fn target(
        &self,
        argv: &[String],
        words: &[Word],
        pushd: bool,
        home: Option<&Path>,
    ) -> Option<Dir> {
        let mut operand = None;
        let mut options_done = false;
        for (i, a) in argv.iter().enumerate().skip(1) {
            if !options_done && a == "--" {
                options_done = true;
                continue;
            }
            if !options_done && a.starts_with(['-', '+']) && a != "-" {
                // `pushd +N` / `-N` rotates the stack: unknown.
                if pushd && a[1..].bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                continue;
            }
            operand = Some((a, words.get(i)));
            break;
        }
        let Some((a, word)) = operand else {
            // `cd` alone goes home; `pushd` alone swaps the top two.
            return (!pushd).then(Dir::home);
        };
        if word.is_some_and(|w| w.has_substitution) || a == "-" {
            return None;
        }
        let (base, rest) = if let Some(rest) = home_prefixed(a) {
            (Dir::home(), rest)
        } else if a.contains('$') || a.starts_with('~') {
            return None;
        } else if let Some(rest) = a.strip_prefix('/') {
            (Dir::root(), rest)
        } else {
            (self.dir.clone()?, a.as_str())
        };
        base.join(rest, home)
    }

    /// `argv` with the path operands of a filesystem-destructive command
    /// (`rm`, `chmod`, `chown`) joined onto the directory an earlier `cd`
    /// left the shell in. `None` when nothing changes: no `cd` ran, the
    /// directory is unknown, or no operand is relative.
    pub(crate) fn rewrite(&self, argv: &[String], home: Option<&Path>) -> Option<Vec<String>> {
        if !self.moved {
            return None;
        }
        let dir = self.dir.as_ref()?;
        // The mode / owner operand of chmod / chown is not a path.
        let mut not_paths = match argv.first().map(String::as_str) {
            Some("rm") => 0,
            Some("chmod" | "chown") => 1,
            _ => return None,
        };
        let mut out = argv.to_vec();
        let mut changed = false;
        let mut options_done = false;
        for a in out.iter_mut().skip(1) {
            if !options_done && a == "--" {
                options_done = true;
                continue;
            }
            if !options_done && a.starts_with('-') {
                continue;
            }
            if not_paths > 0 {
                not_paths -= 1;
                continue;
            }
            if a.is_empty() || a.starts_with(['/', '~', '$']) {
                continue;
            }
            if let Some(joined) = dir.join(a, home) {
                *a = joined.render(home);
                changed = true;
            }
        }
        changed.then_some(out)
    }
}

/// The rest of a path spelled from the home directory (`~`, `~/x`,
/// `$HOME/x`, `${HOME}`), without its leading `/`.
fn home_prefixed(a: &str) -> Option<&str> {
    ["~", "$HOME", "${HOME}"].iter().find_map(|p| {
        let rest = a.strip_prefix(p)?;
        if rest.is_empty() {
            Some(rest)
        } else {
            rest.strip_prefix('/')
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(line: &str) -> Vec<String> {
        line.split(' ').map(str::to_string).collect()
    }

    fn after(cds: &[&str], start: Option<&str>, home: Option<&str>, cmd: &str) -> Option<String> {
        let home = home.map(Path::new);
        let mut cwd = RuleCwd::start(start.map(Path::new));
        for cd in cds {
            let a = argv(cd);
            let words: Vec<Word> = a.iter().map(|_| Word::default()).collect();
            cwd.command(&a, &words, home);
        }
        cwd.rewrite(&argv(cmd), home).map(|v| v.join(" "))
    }

    #[test]
    fn joins_relative_operands_onto_the_cd_target() {
        let r = |cds: &[&str], cmd| after(cds, None, None, cmd);
        assert_eq!(r(&["cd /"], "rm -rf *").as_deref(), Some("rm -rf /*"));
        assert_eq!(r(&["cd ~"], "rm -rf .").as_deref(), Some("rm -rf ~"));
        assert_eq!(
            r(&["cd $HOME"], "rm -rf .*").as_deref(),
            Some("rm -rf ~/.*")
        );
        assert_eq!(
            r(&["cd ${HOME}/x"], "rm -rf ..").as_deref(),
            Some("rm -rf ~")
        );
        assert_eq!(
            r(&["cd /usr", "cd .."], "rm -rf *").as_deref(),
            Some("rm -rf /*")
        );
        assert_eq!(
            r(&["cd /usr/../.."], "rm -rf *").as_deref(),
            Some("rm -rf /*")
        );
        assert_eq!(r(&["cd"], "rm -rf *").as_deref(), Some("rm -rf ~/*"));
        assert_eq!(
            r(&["cd -P -- /"], "rm -rf -- ./a/").as_deref(),
            Some("rm -rf -- /a")
        );
        assert_eq!(
            r(&["cd /"], "chown -R root:root .").as_deref(),
            Some("chown -R root:root /")
        );
        assert_eq!(
            r(&["cd /"], "chmod -R 777 *").as_deref(),
            Some("chmod -R 777 /*")
        );
    }

    #[test]
    fn leaves_the_line_alone_when_nothing_is_known() {
        let r = |cds: &[&str], cmd| after(cds, None, None, cmd);
        assert_eq!(r(&[], "rm -rf *"), None);
        assert_eq!(r(&["cd -"], "rm -rf *"), None);
        assert_eq!(r(&["cd $TMP"], "rm -rf *"), None);
        assert_eq!(r(&["cd ~bob"], "rm -rf *"), None);
        assert_eq!(r(&["cd build"], "rm -rf *"), None);
        assert_eq!(r(&["cd ~", "cd .."], "rm -rf *"), None);
        assert_eq!(r(&["cd /", "popd"], "rm -rf *"), None);
        assert_eq!(r(&["pushd"], "rm -rf *"), None);
        assert_eq!(r(&["pushd +1"], "rm -rf *"), None);
        assert_eq!(r(&["cd /"], "rm -rf /x ~/y $D"), None);
        assert_eq!(r(&["cd /"], "ls *"), None);
    }

    #[test]
    fn a_known_start_resolves_relative_cds() {
        let home = Some("/home/u");
        let start = Some("/home/u/proj");
        let r = |cds: &[&str], cmd| after(cds, start, home, cmd);
        assert_eq!(r(&[], "rm -rf *"), None);
        assert_eq!(
            r(&["cd build"], "rm -rf *").as_deref(),
            Some("rm -rf ~/proj/build/*")
        );
        assert_eq!(r(&["cd .."], "rm -rf *").as_deref(), Some("rm -rf ~/*"));
        assert_eq!(
            r(&["cd ../.."], "rm -rf *").as_deref(),
            Some("rm -rf /home/*")
        );
        assert_eq!(r(&["cd /home/u"], "rm -rf .").as_deref(), Some("rm -rf ~"));
        assert_eq!(
            after(&["cd ~", "cd .."], None, home, "rm -rf *").as_deref(),
            Some("rm -rf /home/*")
        );
    }

    #[test]
    fn a_substitution_target_is_unknown() {
        let mut cwd = RuleCwd::start(None);
        let a = argv("cd $(mktemp)");
        let words = vec![
            Word::default(),
            Word {
                has_substitution: true,
                ..Word::default()
            },
        ];
        cwd.command(&a, &words, None);
        assert_eq!(cwd.rewrite(&argv("rm -rf *"), None), None);
    }
}
