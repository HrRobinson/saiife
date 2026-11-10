//! A scripted `Docker` for tests.

use super::{Docker, Output};
use crate::DevError;
use std::sync::Mutex;

/// One recorded call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub args: Vec<String>,
    pub stdin: Option<Vec<u8>>,
}

#[derive(Default)]
struct State {
    sticky: Vec<(Vec<String>, Output)>,
    once: Vec<(Vec<String>, Output, bool)>,
    calls: Vec<Call>,
}

/// A `Docker` that answers from a script and records what it was asked.
#[derive(Default)]
pub struct FakeDocker {
    state: Mutex<State>,
}

fn owned(prefix: &[&str]) -> Vec<String> {
    prefix.iter().map(|s| s.to_string()).collect()
}

impl FakeDocker {
    pub fn new() -> FakeDocker {
        FakeDocker::default()
    }

    /// Answer every call that starts with `prefix`; a later `on` wins.
    pub fn on(&self, prefix: &[&str], out: Output) -> &Self {
        self.lock().sticky.push((owned(prefix), out));
        self
    }

    /// Answer one call that starts with `prefix`, before any `on`.
    pub fn once(&self, prefix: &[&str], out: Output) -> &Self {
        self.lock().once.push((owned(prefix), out, false));
        self
    }

    /// Every call so far, in order.
    pub fn calls(&self) -> Vec<Call> {
        self.lock().calls.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn matches(prefix: &[String], args: &[&str]) -> bool {
    args.len() >= prefix.len() && prefix.iter().zip(args).all(|(p, a)| p == a)
}

impl Docker for FakeDocker {
    fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Output, DevError> {
        let mut st = self.lock();
        st.calls.push(Call {
            args: owned(args),
            stdin: stdin.map(<[u8]>::to_vec),
        });
        if let Some((_, out, used)) = st
            .once
            .iter_mut()
            .find(|(p, _, used)| !*used && matches(p, args))
        {
            *used = true;
            return Ok(out.clone());
        }
        if let Some((_, out)) = st.sticky.iter().rev().find(|(p, _)| matches(p, args)) {
            return Ok(out.clone());
        }
        Ok(Output::fail(
            125,
            &format!("fake docker: no reply for: {}", args.join(" ")),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn fake_records_and_answers() {
        let f = FakeDocker::new();
        f.on(&["ps"], Output::ok("a"));
        let out = f.run(&["ps", "-a"], Some(b"x")).unwrap();
        assert_eq!(out.stdout, b"a");
        assert_eq!(
            f.calls(),
            vec![Call {
                args: vec!["ps".into(), "-a".into()],
                stdin: Some(b"x".to_vec())
            }]
        );
    }

    #[test]
    fn fake_once_then_sticky() {
        let f = FakeDocker::new();
        f.on(&["ps"], Output::ok("s"));
        f.once(&["ps"], Output::ok("1"));
        let got: Vec<Vec<u8>> = (0..3)
            .map(|_| f.run(&["ps"], None).unwrap().stdout)
            .collect();
        assert_eq!(got, vec![b"1".to_vec(), b"s".to_vec(), b"s".to_vec()]);
    }

    #[test]
    fn fake_later_on_overrides() {
        let f = FakeDocker::new();
        f.on(&["ps"], Output::ok("a"));
        f.on(&["ps"], Output::ok("b"));
        assert_eq!(f.run(&["ps"], None).unwrap().stdout, b"b");
    }

    #[test]
    fn fake_empty_prefix_matches_all() {
        let f = FakeDocker::new();
        f.on(&[], Output::ok("any"));
        assert_eq!(f.run(&["zzz"], None).unwrap().stdout, b"any");
    }

    #[test]
    fn fake_unscripted_is_125() {
        let f = FakeDocker::new();
        let out = f.run(&["network", "ls"], None).unwrap();
        assert_eq!(out.status, 125);
        assert!(String::from_utf8_lossy(&out.stderr).contains("no reply for: network ls"));
    }
}
