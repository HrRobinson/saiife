//! Golden corpus for the wrapper-unwrapping hardening slice — closing the
//! transparent-wrapper bypass gap documented but not covered by the earlier
//! tokenizer work. Each of these ALLOWed today because the wrapper sat at
//! `argv[0]` in place of the real command, so no `^`-anchored pack rule ever
//! matched the destructive command hiding behind it:
//!
//! - **time** — `time rm -rf /` (shell builtin and GNU `/usr/bin/time`).
//! - **timeout** — `timeout 300 rm -rf /`; options + one duration positional.
//! - **chroot** — `chroot /mnt/root rm -rf /`; options + one NEWROOT positional.
//! - **flock** — `flock /tmp/lock rm -rf /`; options + one lockfile positional.
//! - **su -c** — `su -c 'rm -rf /'`; the wrapped command is the `-c` string,
//!   recursed via the proven inline-payload path (`su` is NOT a transparent
//!   prefix — its first operand is a username, so `su rm`/`su root` stay ALLOW).
//! - **watch** — `watch rm -rf /`; watch joins its args and runs them via
//!   `sh -c`, so the joined string is recursed.
//!
//! Still deferred, documented gaps (must remain ALLOW, as today): `xargs`
//! (its catastrophic operand comes from stdin, invisible to a static scan)
//! and the `flock … -c 'STRING'` sub-form.
//!
//! Zero-false-positive discipline: every wrapper has BOTH a deny block (the
//! bypass is now caught) AND a benign block (normal uses still ALLOW). A
//! leading-token skip can only ever *remove* tokens, never fabricate a
//! command, so imperfect option tables cost recall, never precision.

use lfguard::builtins::builtin_packs;
use lfguard::engine::Engine;
use lfguard::profile::select_active;

/// core.filesystem + core.git are default-on; the context for every line
/// below except the gcloud ones.
fn default_engine() -> Engine {
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    Engine::new(select_active(packs, &[]))
}

/// cloud.gcloud is opt-in; the cross-pack gcloud lines need it enabled.
fn gcloud_engine() -> Engine {
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    Engine::new(select_active(packs, &["cloud.gcloud".to_string()]))
}

fn assert_all_deny(e: &Engine, cmds: &[&str]) {
    for cmd in cmds {
        assert!(
            e.evaluate(cmd).is_deny(),
            "expected DENY for {cmd:?}, got {:?}",
            e.evaluate(cmd)
        );
    }
}

fn assert_all_allow(e: &Engine, cmds: &[&str]) {
    for cmd in cmds {
        assert!(
            !e.evaluate(cmd).is_deny(),
            "expected ALLOW for {cmd:?}, got {:?}",
            e.evaluate(cmd)
        );
    }
}

// ---- time ----------------------------------------------------------------

#[test]
fn time_bypass_now_denies() {
    assert_all_deny(
        &default_engine(),
        &[
            "time rm -rf /",
            "time -p rm -rf /",
            "/usr/bin/time -v rm -rf /",
            "/usr/bin/time -o out.txt rm -rf /",
        ],
    );
}

#[test]
fn time_benign_still_allows() {
    assert_all_allow(
        &default_engine(),
        &["time ls", "time -p make", "/usr/bin/time -v ./build.sh"],
    );
}

// ---- timeout -------------------------------------------------------------

#[test]
fn timeout_bypass_now_denies() {
    assert_all_deny(
        &default_engine(),
        &[
            "timeout 300 rm -rf /",
            "timeout 5s rm -rf /",
            "timeout -s KILL 10 rm -rf /",
            "timeout --signal=KILL 10 rm -rf /",
            "timeout -k 5 10 rm -rf /",
        ],
    );
}

#[test]
fn timeout_benign_still_allows() {
    assert_all_allow(
        &default_engine(),
        &[
            "timeout 5 ls",
            "timeout 300 make",
            "timeout 10 curl https://x",
            "timeout 300", // no command
            "timeout",     // bare
        ],
    );
}

// ---- chroot --------------------------------------------------------------

#[test]
fn chroot_bypass_now_denies() {
    assert_all_deny(
        &default_engine(),
        &[
            "chroot /mnt/root rm -rf /",
            "chroot --userspec=root:root /mnt rm -rf /etc",
        ],
    );
}

#[test]
fn chroot_benign_still_allows() {
    assert_all_allow(&default_engine(), &["chroot /mnt/root ls", "chroot /mnt"]);
}

// I-1: chroot separate-value options (`--userspec VALUE`, `--groups VALUE`,
// and BSD short forms `-u`/`-g`/`-G`/`-U`) previously bypassed unwrapping
// because the value token was left in place and misread as NEWROOT.
#[test]
fn chroot_separate_value_options_bypass_now_denies() {
    assert_all_deny(
        &default_engine(),
        &[
            "chroot --userspec root:root /mnt rm -rf /",
            "chroot --groups wheel /mnt rm -rf /",
            "chroot -u root /mnt rm -rf /",
            "chroot -g wheel /mnt rm -rf /",
            "chroot -G wheel /mnt rm -rf /",
            "chroot -U root /mnt rm -rf /",
        ],
    );
}

#[test]
fn chroot_separate_value_options_benign_still_allows() {
    assert_all_allow(
        &default_engine(),
        &[
            "chroot --userspec root:root /mnt ls",
            "chroot --groups wheel /mnt ls",
            "chroot -u root /mnt ls",
        ],
    );
}

// ---- flock ---------------------------------------------------------------

#[test]
fn flock_bypass_now_denies() {
    assert_all_deny(
        &default_engine(),
        &[
            "flock /tmp/lock rm -rf /",
            "flock -w 5 /tmp/lock rm -rf /",
            "flock -n /var/lock/x rm -rf ~",
        ],
    );
}

#[test]
fn flock_benign_still_allows() {
    assert_all_allow(
        &default_engine(),
        &["flock /tmp/lock ls", "flock /tmp/lock echo hi", "flock -n 9"],
    );
}

// ---- su -c ---------------------------------------------------------------

#[test]
fn su_dash_c_bypass_now_denies() {
    assert_all_deny(
        &default_engine(),
        &[
            "su -c 'rm -rf /'",
            "su root -c 'rm -rf /'",
            "su - -c 'rm -rf /'",
            "su -l root -c 'git reset --hard'",
        ],
    );
}

#[test]
fn su_benign_still_allows() {
    assert_all_allow(
        &default_engine(),
        &[
            "su root", // interactive, no command
            "su -c 'ls'",
            r#"su - postgres -c 'psql -c "SELECT 1"'"#,
        ],
    );
}

/// The load-bearing regression: `su` must NOT be treated as a blind prefix.
/// `su rm` means "become user rm", not "run rm" — it must ALLOW. If this ever
/// denies, `su` has been wrongly added to the transparent-prefix path.
#[test]
fn su_non_prefix_regression_stays_allow() {
    assert_all_allow(&default_engine(), &["su rm", "su root"]);
}

// I-2: util-linux `su --command COMMAND` (separate token) and
// `--command=COMMAND` (attached) previously bypassed inline-payload
// extraction, which only matched the exact `-c` token.
#[test]
fn su_dash_dash_command_bypass_now_denies() {
    assert_all_deny(
        &default_engine(),
        &[
            "su --command 'rm -rf /'",
            "su --command='rm -rf /'",
            "su -l root --command 'rm -rf /'",
        ],
    );
}

#[test]
fn su_dash_dash_command_benign_still_allows() {
    assert_all_allow(
        &default_engine(),
        &[
            "su --command 'ls'",
            r#"su --command='psql -c "SELECT 1"'"#,
            "su rm",
            "su root",
        ],
    );
}

// ---- watch ---------------------------------------------------------------

#[test]
fn watch_bypass_now_denies() {
    assert_all_deny(
        &default_engine(),
        &[
            "watch rm -rf /",
            "watch -n 5 rm -rf /",
            "watch -n5 rm -rf /",
            "watch 'rm -rf /'",
        ],
    );
}

#[test]
fn watch_benign_still_allows() {
    assert_all_allow(
        &default_engine(),
        &["watch -n 5 ls", "watch df -h", "watch 'git status'"],
    );
}

// ---- cross-pack (proves the fix is pack-agnostic) ------------------------

#[test]
fn wrappers_are_pack_agnostic() {
    assert_all_deny(
        &gcloud_engine(),
        &[
            "timeout 60 gcloud projects delete p",
            "su -c 'gcloud projects delete p'",
        ],
    );
}

// ---- composition ---------------------------------------------------------

#[test]
fn wrappers_compose_with_other_engine_mechanisms() {
    assert_all_deny(
        &default_engine(),
        &[
            // wrapper stacking: sudo peels, then timeout peels
            "sudo timeout 5 rm -rf /",
            // unwrap then the guarded-argument fail-safe fires
            "timeout 5 rm -rf $(x)",
            // unwrap then command-position substitution recursion
            "timeout 5 $(rm -rf /)",
            // inline payload then unwrap the wrapper inside it
            "bash -c 'timeout 5 rm -rf /'",
        ],
    );
}

// ---- deferred, documented gaps (must remain ALLOW) -----------------------

/// `xargs` is a deferred, accepted limitation: its catastrophic operand
/// arrives on stdin from the producer, which a static scan cannot see. Even
/// unwrapped, `rm -rf` with no target token is (correctly) not catastrophic.
/// This stays ALLOW exactly as it does today — documented, not a regression.
#[test]
fn deferred_xargs_stays_allow() {
    assert_all_allow(&default_engine(), &["find . -name '*.tmp' | xargs rm"]);
}

// ---- structural: latency, depth/termination ------------------------------

/// A 5000-segment chain ending in a wrapper-hidden catastrophe must still be
/// judged and DENY — the per-segment unwrap/recurse work must stay linear, no
/// quadratic blowup. A generous budget is used deliberately so scheduler
/// jitter under a loaded/parallel test run can't trip the engine's own
/// fail-open timeout and mask a real linearity regression; the wall-clock
/// bound is still far below anything a quadratic blowup (~25M segment-evals)
/// could achieve, so it remains a meaningful linearity guard.
#[test]
fn long_chain_with_trailing_wrapper_denies_and_stays_linear() {
    let e = default_engine().with_budget(std::time::Duration::from_secs(5));
    for tail in ["timeout 5 rm -rf /", "su -c 'rm -rf /'"] {
        let mut cmd = String::new();
        for _ in 0..5000 {
            cmd.push_str("true && ");
        }
        cmd.push_str(tail);
        let start = std::time::Instant::now();
        let decision = e.evaluate(&cmd);
        let elapsed = start.elapsed();
        assert!(decision.is_deny(), "expected DENY for tail {tail:?}, got {decision:?}");
        assert!(
            elapsed < std::time::Duration::from_millis(250),
            "5000-segment chain ({tail:?}) took {elapsed:?}, far above linear — possible quadratic blowup"
        );
    }
}

/// Deeply nested wrapper recursion (`watch watch … rm -rf /`, each layer
/// re-recursing through `watch_payload`) past MAX_INLINE_DEPTH must terminate
/// quickly and fail open rather than overflow the stack. The exact cutover is
/// an implementation detail; what matters is it does not hang or panic.
#[test]
fn deep_watch_nesting_fails_open_not_stack_overflow() {
    let e = default_engine();
    let mut cmd = "rm -rf /".to_string();
    for _ in 0..20 {
        cmd = format!("watch {cmd}");
    }
    let start = std::time::Instant::now();
    let _ = e.evaluate(&cmd);
    let elapsed = start.elapsed();
    // Purpose is termination without stack overflow or a hang, not a precise
    // budget — a loose bound keeps it robust under a loaded parallel run.
    assert!(
        elapsed < std::time::Duration::from_millis(250),
        "20-deep watch nesting took {elapsed:?}, expected to terminate quickly"
    );
}

/// Nested `su -c` recursion terminates and is judged (2 levels: alternating
/// quote styles). Proves the su path recurses through the same bounded engine
/// re-entry as `bash -c`.
#[test]
fn nested_su_dash_c_is_judged() {
    let e = default_engine();
    assert!(
        e.evaluate(r#"su -c 'su -c "rm -rf /"'"#).is_deny(),
        "expected DENY for nested su -c"
    );
}
