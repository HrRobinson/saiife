//! Golden corpus for the `core.process` pack: an agent may not signal
//! processes without naming a specific target (`pkill -n`, `pkill -u me`,
//! `kill -9 -1`, `killall5`, a pattern that matches every process).
//! Signalling a named process or a process id stays allowed.
//!
//! Every command is also judged behind the wrappers the engine peels
//! (`timeout 5`, `setsid`, `nice -n 5`, `env`), and with the redirections
//! an agent tacks on (`2>/dev/null`, `2>&1`, `|| true`): they are not
//! operands (fix round 1, I1 and I2).
//!
//! These tests judge command TEXT only; nothing here runs a process tool.

use saiifeguard::builtins::builtin_packs;
use saiifeguard::engine::{Decision, Engine};
use saiifeguard::profile::select_active;

const TEST_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

const WRAPPERS: [&str; 5] = ["", "timeout 5 ", "setsid ", "nice -n 5 ", "env "];

const SUFFIXES: [&str; 8] = [
    "",
    " 2>/dev/null",
    " >/dev/null 2>&1",
    " &>/dev/null",
    " 2>&1",
    " </dev/null",
    " >&1",
    " 2>/dev/null || true",
];

/// Every wrapper and suffix around `cmd`.
fn forms(cmd: &str) -> Vec<String> {
    WRAPPERS
        .iter()
        .flat_map(|w| SUFFIXES.iter().map(move |s| format!("{w}{cmd}{s}")))
        .collect()
}

/// `core.process` alone.
fn engine() -> Engine {
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    let process: Vec<_> = packs
        .into_iter()
        .filter(|p| p.id == "core.process")
        .collect();
    assert_eq!(process.len(), 1, "core.process ships");
    assert!(process[0].default_on, "core.process is on by default");
    Engine::new(process).with_budget(TEST_BUDGET)
}

fn assert_all_deny(e: &Engine, cmds: &[&str]) {
    let mut wrong = Vec::new();
    for cmd in cmds {
        for line in forms(cmd) {
            match e.evaluate(&line) {
                Decision::Deny { pack, reason, .. }
                    if pack == "core.process" && !reason.is_empty() => {}
                other => wrong.push(format!("expected DENY for {line:?}, got {other:?}")),
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

fn assert_all_allow(e: &Engine, cmds: &[&str]) {
    let mut wrong = Vec::new();
    for cmd in cmds {
        for line in forms(cmd) {
            let got = e.evaluate(&line);
            if got.is_deny() {
                wrong.push(format!("expected ALLOW for {line:?}, got {got:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn pkill_newest_or_oldest_without_a_pattern_is_denied() {
    assert_all_deny(
        &engine(),
        &[
            "pkill -n",
            "pkill -o",
            "pkill --newest",
            "pkill --oldest",
            "pkill --new",
            "pkill --old",
            "pkill -9 -n",
            "pkill -KILL -o",
            "pkill -n -9",
            "pkill -SIGKILL --newest",
            "pkill --signal KILL -n",
            "pkill --signal=KILL -o",
            "pkill -e -n",
            "pkill -en",
            "pkill -n --",
            "/usr/bin/pkill -n",
            "sudo pkill -n",
            "xargs pkill -n",
            "bash -c 'pkill -n'",
            "cd /tmp && pkill -o",
        ],
    );
}

#[test]
fn pkill_with_only_selectors_is_denied() {
    assert_all_deny(
        &engine(),
        &[
            "pkill -u jonas",
            "pkill -ujonas",
            "pkill --euid jonas",
            "pkill --euid=jonas",
            "pkill -U 1000",
            "pkill --uid 1000",
            "pkill -g 0",
            "pkill --pgroup 0",
            "pkill -G users",
            "pkill -s 0",
            "pkill --session 0",
            "pkill -P 1",
            "pkill --parent 1",
            "pkill -t pts/1",
            "pkill --terminal pts/1",
            "pkill -9 -u jonas",
            "pkill -KILL -U jonas",
            "pkill -u jonas -n",
            "pkill -O 60",
            "pkill --older 60",
            "pkill -r S",
            "pkill --cgroup /user.slice",
            "pkill --ns 1",
            "pkill --env FOO=1",
            "pkill --frobnicate",
            // A word that may be a signal or an option bundle is judged
            // both ways (S14): `-ttin` is SIGTTIN, or `-t tin`.
            "pkill -ttin",
            "pkill -USR1",
            // A parent, group or session of 0 (pkill's own) or 1 (init),
            // or one not known until it runs, names no target.
            "pkill -P 0",
            "pkill -g 1",
            "pkill -s 1,0",
            "pkill -P $PID",
            "pkill -g \"$G\"",
            "pkill -P 1234,1",
            // Final review S24: a target option given twice, or once
            // without a target, does not name one.
            "pkill -P 1234 -P ''",
            "pkill -P 1234 --parent ''",
            "pkill --parent=1234 -P 0",
            "pkill -g 1234 -g $X",
            "pkill -P 1234 -s 0",
            "xargs kill -1",
            "pkill -u $(whoami) node",
        ],
    );
}

#[test]
fn pkill_inverse_is_denied() {
    assert_all_deny(
        &engine(),
        &[
            "pkill --inverse node",
            "pkill --inv node",
            "pkill -9 --inverse -f 'npm run dev'",
        ],
    );
}

#[test]
fn a_pattern_matching_every_process_is_denied() {
    assert_all_deny(
        &engine(),
        &[
            "pkill .",
            "pkill ''",
            "pkill \"\"",
            "pkill -f .",
            "pkill -f ''",
            "pkill '.*'",
            "pkill '^'",
            "pkill -9 .",
            "pkill -u jonas .",
            "pkill -f -- '.*'",
            "killall -r .",
            "killall -r '.*'",
            "killall --regexp '^'",
            "killall -9 -r .",
            // After `--` a word starting with `-` is a pattern too (S15).
            "pkill -- '-*.'",
            "pkill -n -- '-*.'",
            "killall -r -- '-*.'",
            // Most names (S16): a one-character pattern, a class.
            "pkill e",
            "pkill s",
            "pkill -f /",
            "pkill -f ' '",
            "pkill '[a-z]'",
            "pkill -f '[a-z]'",
            "pkill -9 -i '[a-z]'",
            "killall -r '[a-z]'",
            "killall -r e",
        ],
    );
}

#[test]
fn killall_without_a_name_is_denied() {
    assert_all_deny(
        &engine(),
        &[
            "killall -u jonas",
            "killall -ujonas",
            "killall -9 -u jonas",
            "killall -KILL -u jonas",
            "killall --user jonas",
            "killall --user=jonas",
            "killall -user jonas",
            "killall -s KILL -u jonas",
            "killall -Z 'unconfined_t'",
            "killall -u jonas --",
            "killall5",
            "killall5 -9",
            "killall5 -15 -o 1234",
            "/usr/bin/killall5",
        ],
    );
}

#[test]
fn kill_of_every_process_the_group_or_init_is_denied() {
    assert_all_deny(
        &engine(),
        &[
            // -1: every process the user may signal.
            "kill -9 -1",
            "kill -KILL -1",
            "kill -SIGKILL -1",
            "kill -- -1",
            "kill -9 -- -1",
            "kill -s KILL -1",
            "kill -s 9 -1",
            "kill -n 9 -1",
            "kill --signal KILL -1",
            "kill --signal=KILL -1",
            "kill 1234 -1",
            "kill -9 1234 -1",
            "kill -9 -001",
            // A lone `-1` or `-0` is a signal with no pid, or a pid: both
            // readings are judged.
            "kill -1",
            "kill -0",
            // 0 / -0: the caller's own process group.
            "kill 0",
            "kill 00",
            "kill -9 0",
            "kill -TERM 0",
            "kill -- 0",
            "kill -- -0",
            "kill -9 -0",
            "kill 1234 0",
            // 1: init.
            "kill 1",
            "kill +1",
            "kill 01",
            "kill -9 1",
            "kill -TERM 1",
            "kill -s TERM 1",
            "kill -- 1",
            "kill 1:12345",
            "/bin/kill -9 -1",
            "/usr/bin/kill 0",
            // A pid from arithmetic (S17).
            "kill -9 $((-1))",
            "kill $((0))",
            "kill -9 $((PID-1))",
            "kill -9 -- $((1))",
        ],
    );
}

#[test]
fn a_pattern_from_a_substitution_is_denied() {
    assert_all_deny(
        &engine(),
        &[
            "pkill $(cat name.txt)",
            "pkill -f \"$(cat pattern.txt)\"",
            "pkill -n $(cat name.txt)",
            "pkill -f `cat pattern.txt`",
            "killall $(cat names.txt)",
            "killall -r \"$(cat pattern.txt)\"",
        ],
    );
}

/// Final review I5a: an option's value is not a pattern, and a parent,
/// process group or session given as literal ids (above 1) or `$$` names a
/// target.
#[test]
fn option_values_and_targeted_selectors_are_allowed() {
    assert_all_allow(
        &engine(),
        &[
            "pkill --signal 9 node",
            "pkill --signal=9 node",
            "pkill -u 0 node",
            "pkill -q 5 node",
            "pkill -U 1000 -x node",
            "killall -r -s 9 '^node$'",
            "killall -s 9 node",
            "killall --signal 9 -r '^node$'",
            "pkill -P 1234",
            "pkill -P $$",
            "pkill -g 1234",
            "pkill --pgroup 1234",
            "pkill -s 4321",
            "pkill -P 1234,5678",
            "pkill -9 -P 1234",
            "pkill -n -P 1234",
        ],
    );
}

/// Final review M1 / S23: a pattern holding a parameter expansion is not
/// known until it runs (it may be empty, or anything): it counts as a
/// match.
#[test]
fn a_pattern_with_an_expansion_is_denied() {
    assert_all_deny(
        &engine(),
        &[
            "pkill \"$X\"",
            "pkill $X",
            "pkill \"${X}\"",
            "pkill -f \"$X\"",
            "pkill -f \"${PATTERN}\"",
            "pkill -9 \"$1\"",
            "pkill \"$X$Y\"",
            "pkill \"x$X\"",
            "pkill \"sa${X}fed\"",
            "pkill \"${X}node\"",
            "pkill \"$APP-server\"",
            "pkill -f \"node $APP\"",
            "killall -r \"$X\"",
            "killall -r \"${X}\"",
            "killall \"$NAME\"",
            "killall \"${X}nginx\"",
        ],
    );
    assert_all_allow(&engine(), &["pkill node", "pkill -f 'npm run dev'"]);
}

/// Security review: Rust regex class set operations (`&&`, `--`, `~~`)
/// mean something else to pkill's ERE and to fnmatch: such a pattern
/// counts as a match.
#[test]
fn class_set_operations_count_as_a_match() {
    assert_all_deny(
        &engine(),
        &[
            "pkill '[a-z&&[^x]]x'",
            "pkill '[a-z--b]xy'",
            "pkill '[a-z~~b]xy'",
            "killall -r '[a-z&&[^x]]x'",
        ],
    );
}

#[test]
fn targeted_kills_are_allowed() {
    assert_all_allow(
        &engine(),
        &[
            "kill 12345",
            "kill %1",
            "kill -9 %1",
            "kill -9 12345",
            "kill -TERM 12345",
            "kill -1 12345",
            "kill -HUP 12345",
            "kill -0 12345",
            "kill -s HUP 12345",
            "kill -s 1 12345",
            "kill -n 1 12345",
            "kill -9 -12345",
            "kill -- -12345",
            "kill 10",
            "kill 100 101",
            "kill -l",
            "kill -l 1",
            "kill -L",
            "kill -d 12345",
            "kill $(cat app.pid)",
            "pkill node",
            "pkill -f 'npm run dev'",
            "pkill -9 -f 'npm run dev'",
            "pkill -HUP node",
            "pkill -TERM node",
            "pkill -n node",
            "pkill -o -f vite",
            "pkill -u jonas node",
            "pkill -x node",
            "pkill -F app.pid",
            "pkill --pidfile app.pid",
            "pkill -p 12345",
            "killall node",
            "killall -HUP nginx",
            "killall -9 node",
            "killall -u jonas node",
            "killall -r '^node$'",
            "killall -l",
            "killall -V",
            "pgrep -a node",
            "pgrep -n",
            "pgrep -u jonas",
            "pgrep -f .",
            "echo kill -9 -1",
            "grep 'pkill -n' notes.txt",
            // A redirection target is not a pid (I2).
            "kill 1234 2>&1",
            "kill -9 1234 2>&1",
            "kill -9 $PID >/dev/null 2>&1",
            "kill $PID 2>&1 || true",
            "kill -0 $PID 2>&1",
            "kill $(cat .pid) 2>&1 || true",
            "kill -9 -- $PID 2>&1",
            "kill $PID >&1",
            "kill $PID 1>&2",
            "kill $PID 0</dev/null",
            "kill $(cat *.pid)",
            "kill $(pgrep node)",
            "kill $(lsof -ti:3000)",
            "kill $PID",
            "kill -9 $PID",
            "kill -9 -$PGID",
            // Two characters or more name few enough processes (S16).
            "pkill sh",
            "pkill no",
            "pkill -f server.js",
            "pkill -f 'python3 -m http.server'",
            "pkill -- node",
            "killall -r '^vite'",
        ],
    );
}

/// With every default-on pack active, the broad kills are still denied
/// and named by `core.process`.
#[test]
fn default_packs_deny_broad_kills() {
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "{warnings:?}");
    let active = select_active(packs, &[]);
    assert!(
        active.iter().any(|p| p.id == "core.process"),
        "core.process is among the default-on packs"
    );
    let e = Engine::new(active).with_budget(TEST_BUDGET);
    for cmd in [
        "pkill -n",
        "pkill -o",
        "kill -9 -1",
        "killall5",
        "pkill -u jonas",
    ] {
        match e.evaluate(cmd) {
            Decision::Deny { pack, .. } => assert_eq!(pack, "core.process", "{cmd}"),
            other => panic!("expected DENY for {cmd:?}, got {other:?}"),
        }
    }
    for cmd in ["kill 12345", "pkill node", "killall -HUP nginx"] {
        assert!(!e.evaluate(cmd).is_deny(), "{cmd}");
    }
}
