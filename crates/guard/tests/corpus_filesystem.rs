//! Golden corpus for `core.filesystem` (default-on, catastrophic-only).

use saiifeguard::builtins::builtin_packs;
use saiifeguard::engine::{AllowTrace, Decision, Engine};
use saiifeguard::profile::select_active;

fn engine() -> Engine {
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    // core.filesystem is default-on, so the default profile suffices.
    Engine::new(select_active(packs, &[])).with_budget(TEST_BUDGET)
}

fn deny_pack(e: &Engine, cmd: &str) -> String {
    match e.evaluate(cmd) {
        Decision::Deny { pack, .. } => pack,
        other => panic!("expected DENY for {cmd:?}, got {other:?}"),
    }
}

#[test]
fn denies_catastrophic_filesystem_commands() {
    let e = engine();
    let deny = [
        "rm -rf /",
        "rm -rf /*",
        "rm -fr ~",
        "rm -Rf /etc",
        "rm -rf $HOME",
        "rm -r -f /",
        "rm -f -r /usr",
        "rm --recursive --force /var",
        "sudo rm -rf /",
        "rm -rf --no-preserve-root /",
        "dd if=/dev/zero of=/dev/sda",
        "sudo dd if=/dev/zero of=/dev/disk0 bs=1m",
        "mkfs.ext4 /dev/sdb",
        "mkfs -t ext4 /dev/sdb1",
        "truncate -s 0 /dev/sda",
        "echo x > /dev/sda",
        "chmod -R 777 /",
        "chmod -R 000 /etc",
        "chown -R root:root /",
        // I3: quoting variants — the target is wrapped in quotes.
        r#"rm -rf "/""#,
        "rm -rf '/'",
        r#"rm -rf "/etc""#,
        "rm -rf '~'",
        // I3: repeated-slash variants of the root.
        "rm -rf //",
        "rm -rf ///",
        "rm -rf //etc",
        // I3: flags after the target instead of before it.
        "rm /etc -rf",
        "rm / --recursive",
        "rm ~ -fr",
        "sudo rm /etc -rf",
        // The home folder's dotfiles (`.ssh`, `.config`, …).
        "rm -rf ~/.*",
        "rm -rf $HOME/.*",
    ];
    for cmd in deny {
        assert_eq!(deny_pack(&e, cmd), "core.filesystem", "for {cmd:?}");
    }
}

#[test]
fn allows_ordinary_filesystem_commands() {
    let e = engine();
    let allow = [
        "rm -rf ./build",
        "rm -rf node_modules",
        "rm -rf /tmp/scratch",
        "rm -rf /var/folders/xy/tmpdir", // deep temp path, not a system root
        "rm file.txt",
        "rm -r somedir",
        "dd if=/dev/zero of=./out.img bs=1M count=10",
        "chmod -R 755 ./assets",
        "chmod 600 ~/.ssh/id_rsa",
        "chown user:group ./file",
        "truncate -s 0 logfile.txt",
        "mv a b",
        "cp -r src dst",
    ];
    for cmd in allow {
        assert!(
            !e.evaluate(cmd).is_deny(),
            "expected ALLOW for {cmd:?}, got DENY"
        );
    }
}

#[test]
fn leading_redirections_and_assignments_are_still_judged() {
    let e = engine();
    for cmd in [
        ">/dev/sda cat x",
        ">/dev/sda",
        "echo x >/dev/sda",
        "2>&1 >/dev/sda echo x",
        "A+=1 rm -rf /",
        "a[0]=1 rm -rf /",
        "a[i+1]+=x rm -rf /",
    ] {
        assert_eq!(deny_pack(&e, cmd), "core.filesystem", "{cmd}");
    }
    // A quoted word is never an assignment: this runs a command named
    // `FOO=1`, not `rm`.
    assert!(!e.evaluate(r#""FOO=1" rm -rf /"#).is_deny());
    assert!(!e.evaluate(r#"FOO"=1" rm -rf /"#).is_deny());
}

#[test]
fn heredoc_substitutions_are_judged() {
    let e = engine();
    assert_eq!(
        deny_pack(&e, "cat <<EOF\n$(rm -rf /)\nEOF"),
        "core.filesystem"
    );
    assert!(!e.evaluate("cat <<'EOF'\n$(rm -rf /)\nEOF").is_deny());
}

#[test]
fn literal_substitution_values_are_judged() {
    let e = engine();
    for cmd in [
        "rm -rf \"$(cat <<'EOF'\n/\nEOF\n)\"",
        "rm -rf $(echo /)",
        "rm -rf \"$(printf /)\"",
        "rm -rf $(cat /tmp/list)",
    ] {
        deny_pack(&e, cmd);
    }
}

#[test]
fn rm_targets_are_judged_against_an_earlier_cd() {
    let e = engine();
    for cmd in [
        "cd / && rm -rf *",
        "cd /; rm -rf *",
        "cd ~ && rm -rf *",
        "cd $HOME && rm -rf .",
        "cd ~ || exit; rm -rf .*",
        "(cd / && rm -rf *)",
        "bash -c 'cd / && rm -rf *'",
        "cd /usr && cd .. && rm -rf *",
        // Also: a newline, `pushd`, `cd` with no operand (home), options.
        "cd /\nrm -rf *",
        "pushd / && rm -rf *",
        "cd && rm -rf *",
        "cd -P -- / && rm -rf ./*",
        "cd ${HOME} && rm -rf *",
        "cd / && chmod -R 777 .",
        "cd / && chown -R root:root .",
        "cd / && sudo rm -rf *",
        // A cd that may be skipped adds a directory, never replaces one.
        "cd / || cd /tmp; rm -rf *",
        "cd /; false && cd /tmp; rm -rf *",
        "cd /; if false; then cd /tmp; fi; rm -rf *",
        "cd /; false && { cd /tmp; }; rm -rf *",
        "cd /; case x in a) cd /tmp;; esac; rm -rf *",
        "cd / ; (case x in a) ;; esac; cd /tmp) ; rm -rf *",
        // A cd used as a condition still runs.
        "if cd /; then rm -rf *; fi",
        "while cd /; do rm -rf *; done",
        "until cd /; do :; done; rm -rf *",
        "! cd /; rm -rf *",
        "if cd /; then :; fi; rm -rf *",
        // eval runs in this shell.
        "eval cd /; rm -rf *",
        // `pushd -n` only edits the stack.
        "cd / && pushd -n /tmp && rm -rf *",
        // A cd whose failure runs the next command (re-review N2).
        "cd /; ! cd /tmp && rm -rf *",
        "cd /; ! cd /nonexistent && rm -rf *",
        "cd /etc; ! cd /tmp && rm -rf *",
        "cd /; time ! cd /tmp && rm -rf *",
        "cd /; until cd /tmp; do rm -rf *; done",
        "cd /; while ! cd /tmp; do rm -rf *; done",
        "cd /; if ! cd /tmp; then rm -rf *; fi",
        "cd /; if cd /tmp; then :; else rm -rf *; fi",
        "cd /; if cd /tmp; then :; elif true; then rm -rf *; fi",
        // A `cd` shell function (re-review N3): its body's cd counts.
        "function cd { builtin cd /; }; cd /tmp && rm -rf *",
        "cd() { builtin cd /; }; cd /tmp && rm -rf *",
        // Overflow is sticky (re-review N1).
        &*format!(
            "{}cd /etc; cd . && rm -rf *",
            (0..16).map(|i| format!("cd /t{i}; ")).collect::<String>()
        ),
        &*format!(
            "{}cd /etc; cd x && cd .. && rm -rf *",
            (0..16).map(|i| format!("cd /t{i}; ")).collect::<String>()
        ),
        // `!` / `time [-p]` in front of a block head or a cd.
        "time if cd /; then rm -rf *; fi",
        "! time cd /; rm -rf *",
        "time -p cd / && rm -rf *",
        "! if cd /; then rm -rf *; fi",
        // A function body may never run.
        "cd /; f() { cd /tmp; }; rm -rf *",
        "cd /; f () ( cd /tmp ); rm -rf *",
        "cd /; function f { cd /tmp; }; rm -rf *",
        "cd /; function f() { cd /tmp; }; rm -rf *",
        // A cd not followed by `&&` may fail: it only adds.
        "cd /; cd /nonexistent; rm -rf *",
        "cd /; cd /a || cd /b; rm -rf *",
        "cd /; { cd /tmp; } || true; rm -rf *",
        "cd / && cd /tmp && true || rm -rf *",
        "cd /; false && cd /tmp && true; rm -rf *",
        "cd /; if cd /tmp; then :; fi; rm -rf *",
        // Past the bound of possible directories, the held ones are kept.
        &*format!(
            "cd /; {}rm -rf *",
            (b'a'..=b'q')
                .map(|c| format!("true && cd /{}; ", c as char))
                .collect::<String>()
        ),
        &*format!("cd /; {}rm -rf *", "true && cd x; ".repeat(18)),
        &*format!(
            "cd /; if false; then {}fi; rm -rf *",
            (b'a'..=b'q')
                .map(|c| format!("cd /{}; ", c as char))
                .collect::<String>()
        ),
        &*format!(
            "cd ~; {}rm -rf .",
            (b'a'..=b'q')
                .map(|c| format!("true && cd /{}; ", c as char))
                .collect::<String>()
        ),
        &*format!("{}cd /; rm -rf *", "cd /tmp; ".repeat(17)),
        // Past the bound a relative destructive target cannot be judged.
        &*format!(
            "{}cd /etc; rm -rf *",
            (b'a'..=b'p')
                .map(|c| format!("true && cd /{}; ", c as char))
                .collect::<String>()
        ),
        &*format!(
            "{}rm -rf ./build",
            (b'a'..=b'q')
                .map(|c| format!("true && cd /{}; ", c as char))
                .collect::<String>()
        ),
        // chmod / chown on everything under the root.
        "chmod -R 777 /*",
        "cd / && chmod -R 777 *",
        "cd / && chown -R root *",
    ] {
        assert_eq!(deny_pack(&e, cmd), "core.filesystem", "for {cmd:?}");
    }
}

/// Every `cd` target adds to the directories a later target is judged
/// against: whether the `cd` worked, ran, or ran in a subshell is not
/// modelled. These are blocked although they are safe (accepted).
#[test]
fn every_cd_target_counts_even_when_bash_would_not_be_there() {
    let e = engine();
    for cmd in [
        "(cd /); rm -rf *",
        "cd / | rm -rf *",
        "cd / & rm -rf *",
        "cd /; cd proj && rm -rf *",
        "cd / && cd /tmp && rm -rf *",
    ] {
        assert_eq!(deny_pack(&e, cmd), "core.filesystem", "for {cmd:?}");
    }
}

#[test]
fn a_cd_that_cannot_reach_a_catastrophic_target_still_allows() {
    let e = engine();
    for cmd in [
        "cd /tmp && rm -rf ./build",
        // A relative cd into a project subdirectory.
        "cd build && rm -rf *",
        "(cd / && ls) && rm -rf ./dist",
        // Unknown working directory: judged as written (today's verdict).
        "cd \"$(mktemp -d)\" && rm -rf *",
        "cd - && rm -rf *",
        "cd $TMPDIR && rm -rf *",
        "cd ~other && rm -rf *",
        "popd && rm -rf *",
        // `..` above an unknown home is unknown.
        "cd ~ && cd .. && rm -rf ./x",
        // The mode / owner operand is not a path.
        "cd /tmp && chown -R -v root ./x",
        // Other packs see the command unchanged.
        "cd / && git status",
        "cd /tmp || exit; rm -rf *",
        "if cd build; then rm -rf *; fi",
        "eval cd /tmp; rm -rf *",
        "chmod -R u+w ./build",
        "cd /tmp && chmod -R 777 *",
        "cd /tmp; rm -rf *",
        "cd /tmp && cd build && rm -rf *",
        "if cd /tmp; then rm -rf *; fi",
        "while cd /tmp; do rm -rf *; done",
        "f() { cd /; }; rm -rf ./x",
    ] {
        let got = e.evaluate(cmd);
        assert!(!got.is_deny(), "expected ALLOW for {cmd:?}, got {got:?}");
    }
    // Past the bound, a line without a relative destructive target is
    // judged as before.
    let many: String = (b'a'..=b'q')
        .map(|c| format!("true && cd /{}; ", c as char))
        .collect();
    for tail in ["ls", "rm -rf /tmp/x", "cat notes.txt"] {
        let cmd = format!("{many}{tail}");
        let got = e.evaluate(&cmd);
        assert!(!got.is_deny(), "expected ALLOW for {cmd:?}, got {got:?}");
    }
    // An unknown cwd keeps today's verdict exactly (pinned before cd
    // tracking judged rm targets).
    assert_eq!(
        e.evaluate("cd \"$(mktemp -d)\" && rm -rf *"),
        Decision::Allow {
            trace: AllowTrace::Unjudgeable {
                reason: "working directory unknown after cd".into()
            }
        }
    );
}

/// Generous budget so a loaded runner cannot turn a deny into a latency
/// fail-open; the budget path itself is covered by dedicated tests.
const TEST_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

/// cd tracking stops after a bounded number of `cd`s, so a long chain of
/// them costs time linear in its length (re-review N5).
#[test]
fn a_long_cd_chain_stays_cheap() {
    let e = engine();
    let time = |n: usize| {
        let line = format!("true{} && rm -rf *", " && cd x".repeat(n));
        let t = std::time::Instant::now();
        let got = e.evaluate(&line);
        (t.elapsed(), got)
    };
    let (small, _) = time(1_000);
    let (large, got) = time(10_000);
    eprintln!("1k: {small:?}, 10k: {large:?}");
    // Past the bound the relative target is denied, not timed out.
    assert!(got.is_deny(), "{got:?}");
    // Linear: ten times the cds, well under a hundred times the time.
    assert!(
        large < small * 30 + std::time::Duration::from_millis(20),
        "1k {small:?}, 10k {large:?}"
    );
}
