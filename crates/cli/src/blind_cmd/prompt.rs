//! Where `saiife blind ask` reads its answers: prompts on stderr, one line
//! from stdin. Only a terminal is interactive; debug builds also take
//! `SAIIFE_TEST_BLIND_STDIN=1` (the tests' answers on a pipe).

use super::Prompter;
use std::io::{BufRead, IsTerminal, Read, Write};

/// The longest answer line read.
const MAX_LINE: u64 = 4096;

pub(crate) struct Stdin {
    interactive: bool,
}

impl Stdin {
    pub(crate) fn new() -> Stdin {
        Stdin {
            interactive: std::io::stdin().is_terminal() || seam(),
        }
    }
}

/// `SAIIFE_TEST_BLIND_STDIN=1` (debug builds only): answers from a pipe.
#[cfg(debug_assertions)]
fn seam() -> bool {
    std::env::var_os("SAIIFE_TEST_BLIND_STDIN").is_some_and(|v| v == "1")
}

#[cfg(not(debug_assertions))]
fn seam() -> bool {
    false
}

impl Prompter for Stdin {
    fn line(&mut self, prompt: &str) -> Result<String, String> {
        eprint!("{prompt}");
        let _ = std::io::stderr().flush();
        let mut s = String::new();
        let n = std::io::stdin()
            .lock()
            .take(MAX_LINE)
            .read_line(&mut s)
            .map_err(|e| format!("cannot read the answer: {e}"))?;
        if n == 0 {
            return Err("no answer was given".into());
        }
        Ok(s.trim().to_string())
    }

    fn is_interactive(&self) -> bool {
        self.interactive
    }
}

/// A scripted prompter for unit tests: each `line` takes the next answer.
#[cfg(test)]
pub(crate) struct Script {
    pub(crate) answers: std::collections::VecDeque<String>,
    pub(crate) prompts: Vec<String>,
    pub(crate) interactive: bool,
}

#[cfg(test)]
impl Prompter for Script {
    fn line(&mut self, prompt: &str) -> Result<String, String> {
        self.prompts.push(prompt.to_string());
        self.answers
            .pop_front()
            .ok_or_else(|| "no answer was given".to_string())
    }

    fn is_interactive(&self) -> bool {
        self.interactive
    }
}
