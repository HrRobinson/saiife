# Plan 5a: Hardening before release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the code items carried over from plans 1–4 that must land before v1 ships. These are: split the two oversized security-core functions, scope allow rules to their own pack, protect the agents' own credential files, verify here-document handling against real shells, make `status` faster and clearer, cut the per-call hook cost, and fix the small housekeeping items.

**Architecture:** Plan 5 is split into three plans, and this is the first. Plan 5b covers docs, the demo and the live Codex/Gemini checks. Plan 5c covers the release and `install.sh`. Here, the two refactors go first and change no behavior: every existing test and corpus case stays green, and none of them is edited. The behavior changes come after the refactors, each with its own tests.

**Tech Stack:** Rust 2021 workspace (`crates/guard`, `crates/audit`, `crates/agents`, `crates/cli`). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-13-saiife-cli-v1-design.md` (§1.2 principles, §6, §7, §7.5, §8, §10). The carry-over lists are in `docs/superpowers/plans/2026-10-13-saiife-v1-roadmap.md`.

## Global Constraints

- Tests point HOME, PATH, `SAIIFE_DATA_DIR` and `SAIIFE_AUDIT_DIR` at tempdirs. Never run `saiife init` against the real home or the repo. /tmp has a per-user quota, so scratch dirs go under `mktemp -d -p /home/jonas/projects/personal/saiife`.
- No new dependencies. No network use at runtime (§1.2.7). `scripts/test-offline.sh` must pass.
- Work on branch `plan-5a-hardening`. Main changes only land through a PR with green `test (ubuntu-latest)`, `test (macos-latest)` and `offline`.
- Every commit runs `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace --no-fail-fast`.
- Fail open where a human is present (§1.2.4), and every fail-open is visible (§1.2.5).
- Refactor tasks (1, 2) change no observable behavior. No existing test or corpus file is edited in them, except to update an `use` path.

## Review Focus

1. **A refactor that silently changes a decision.** Some command lines are judged only through nested evaluation (`$(…)`, `bash -c`, `eval`, here-documents), and they must decide exactly as before. Owned by Task 1 (`refactor_equivalence_corpus`).
2. **Allow scoping lets through something that was meant to be allowed.** Example: `git reset --hard HEAD~1` is allowed by core.git's own allow rule. It must stay allowed, because no other pack denies it. Owned by Task 3 (`own_pack_allow_still_allows`).
3. **The credential-file rule blocks normal agent work.** Reading `~/.claude/settings.json`, `~/.codex/config.toml` or `~/.gemini/settings.json` must stay allowed, because core.self explains its setup from them. Owned by Task 4 (`agent_settings_stay_readable`).
4. **A slow or huge audit log makes `status` slow.** With 200 000 records spread over 24 monthly files, `status` reads only the files it needs and stays under 1 s in a debug build. Owned by Task 6 (`status_reads_recent_months_only`).
5. **Lazy loading drops a pack's warning or a fail-open.** A broken built-in or project pack still shows its warning, and a pack that `check` does not need is never silently treated as passed. Owned by Task 8 (`lazy_packs_keep_warnings`).

---

### Task 1: Split `Engine::evaluate_inner` (no behavior change)

`evaluate_inner` in `crates/guard/src/engine.rs` (lines 317–882, about 565 lines) passes the shell state through eight arguments, and repeats the "recurse into nested text" block for command-position substitutions, embedded substitutions, inline payloads and `eval`.

**Files:**
- Modify: `crates/guard/src/engine.rs`
- Create: `crates/guard/tests/refactor_equivalence.rs`

**Interfaces:**
- Produces (private to `engine.rs`):

```rust
#[derive(Clone)]
struct ShellState { cwds: Vec<PathBuf>, cwd_unknown: bool, env_changed: bool, ifs_named: bool }
enum Nested { Deny(Decision), Unjudged(String), TimedOut, Clean }
impl Engine {
    fn evaluate_inner(&self, raw_cmd: &str, start: Instant, depth: u32, state: &ShellState, sub_body: bool) -> Decision;
    /// The one place that enforces MAX_INLINE_DEPTH, the budget, and the
    /// "… nested too deeply to judge" note.
    fn recurse(&self, inner: &str, start: Instant, depth: u32, state: &ShellState, sub_body: bool, what: &str) -> Nested;
}
```

  Each phase of the per-segment loop becomes its own method, taking `&mut ShellState` where it updates state. The phases are:
  - command-position substitution;
  - embedded substitutions;
  - inline payloads and `eval`;
  - environment change;
  - `cd`;
  - operands and path rules;
  - command rules.

  No function in `engine.rs`, outside tests, may exceed 120 lines.

- [ ] **Step 1: Pin today's behavior.** Write `crates/guard/tests/refactor_equivalence.rs` with test `refactor_equivalence_corpus`. It has a table of at least 60 command lines with their expected `Decision` kind (allow, deny with pack id, or allow with an Unjudgeable reason substring). The lines come from the existing corpus files and cover each nested path:
  - `$(…)` as the command, and nested;
  - backticks;
  - `bash -c` and `sh -c '…'`;
  - `eval`;
  - here-documents inside `$(…)`, including the Claude Code commit shape `git commit -m "$(cat <<'EOF' … EOF)"`;
  - `cd` followed by path rules;
  - `cd $(…)` (unknown cwd);
  - `IFS` on the line;
  - an environment change followed by a nested agent;
  - the depth cap.

  Get each expected value by running the current engine (on `main` at the plan's base) through `saiife explain`, in a tempdir copy. The test uses the same engine setup as the corpus tests.
- [ ] **Step 2: Run `cargo test -p saiife-guard --test refactor_equivalence`.** Expected: PASS against the unrefactored code.
- [ ] **Step 3: Refactor** to the interface above. Keep comments with the code they explain.
- [ ] **Step 4: Run `cargo test --workspace --no-fail-fast`.** Expected: every test passes, with no test file edited apart from the new one.
- [ ] **Step 5: Commit** with message `refactor(guard): split evaluate_inner into ShellState + recurse + phase methods`.

---

### Task 2: Split the lexer's `lex_in` (no behavior change)

`lex_in` in `crates/guard/src/lexer.rs` (lines 271–807, about 535 lines) handles every token class in one loop.

**Files:**
- Modify: `crates/guard/src/lexer.rs`

**Interfaces:**
- `lex_in`'s signature and every `pub`/`pub(crate)` function stay unchanged. The loop body moves into private helpers, one per token class:
  - quotes and escapes;
  - `$`-forms (substitution, arithmetic, ANSI-C);
  - redirections and here-document openers;
  - operators and segment ends;
  - comments;
  - keywords and grouping.

  Each helper returns whether the main loop continues. No function in `lexer.rs`, outside tests, may exceed 120 lines.

- [ ] **Step 1: Run `cargo test -p saiife-guard`** and record the pass count in the report.
- [ ] **Step 2: Refactor** to the shape above.
- [ ] **Step 3: Run `cargo test --workspace --no-fail-fast`.** Expected: the same pass count with no test edited, including `refactor_equivalence` from Task 1.
- [ ] **Step 4: Commit** with message `refactor(guard): split lex_in into per-token-class helpers`.

---

### Task 3: Allow rules only exempt their own pack

Today, in `Engine::judge` (`engine.rs`, around line 1164), an `[[allow]]` match returns Allow at once, so later packs' deny rules are never checked. The fix: an allow match in pack P skips only P's own deny rules, the same way `allow_path` already works.

**Files:**
- Modify: `crates/guard/src/engine.rs` (`judge`), `crates/guard/src/pack.rs` (module doc: describe the scoping)
- Test: `crates/guard/src/engine.rs` tests, `crates/guard/tests/cross_pack.rs`

**Interfaces:**
- `judge` keeps its signature. It returns `Decided(Deny)` for the first deny in pack order from a pack with no matching allow. Otherwise it returns `Decided(Allow { AllowRule })` for the first matching allow, and otherwise `Clean`.

- [ ] **Step 1: Write failing tests.**
  - `allow_in_one_pack_does_not_hide_another_packs_deny`. Pack A has `[[allow]] pattern="^foo"`. Pack B, loaded after A, has `[[deny]] pattern="^foo bar"`. `foo bar` is denied by B.
  - `own_pack_allow_still_allows`. With the built-in default packs, `git reset --hard HEAD~1` is allowed with an `AllowRule` trace from `core.git`, and `git push --force-with-lease` is allowed.
  - Keep `allow_rule_beats_deny`, which covers the same pack, unchanged.
- [ ] **Step 2: Run `cargo test -p saiife-guard allow`.** Expected: the first test FAILS.
- [ ] **Step 3: Implement** the scoping in `judge`.
- [ ] **Step 4: Run `cargo test --workspace --no-fail-fast`.** If a corpus case changes, stop and report it as DONE_WITH_CONCERNS, quoting the case. Do not edit corpus expectations.
- [ ] **Step 5: Strike the roadmap line.** Strike the plan-5 follow-up "scope `[[allow]]` regex rules" in the roadmap's plan-3 carry-over, in the `~~…~~ — done in plan 5a: …` style.
- [ ] **Step 6: Commit** with message `fix(guard): an allow rule only exempts its own pack's deny rules`.

---

### Task 4: Protect the agents' own credential files

**Files:**
- Modify: `crates/guard/packs/core.secrets.toml`
- Test: `crates/guard/tests/corpus_secrets.rs`

- [ ] **Step 1: Write failing tests** in `corpus_secrets.rs`. Use the corpus's existing HOME-in-tempdir setup.
  - `agent_credential_files_are_secret`. These are denied by `core.secrets`, both as a Read path and as `cat <path>`:
    - `~/.claude/.credentials.json`
    - `~/.codex/auth.json`
    - `~/.gemini/oauth_creds.json`
    - `$CLAUDE_CONFIG_DIR/.credentials.json`, when that variable is bound
    - `$CODEX_HOME/auth.json`, when that variable is bound
  - `agent_settings_stay_readable`. These are allowed for reading:
    - `~/.claude/settings.json`
    - `~/.codex/config.toml`
    - `~/.gemini/settings.json`
- [ ] **Step 2: Run `cargo test -p saiife-guard --test corpus_secrets`.** Expected: FAIL.
- [ ] **Step 3: Add the rules.** Add five `[[deny_path]]` rules with `access = "read"`, reason `"the agent's own login token; reading it lets the agent act as you elsewhere"`, and the globs `~/.claude/.credentials.json`, `$CLAUDE_CONFIG_DIR/.credentials.json`, `~/.codex/auth.json`, `$CODEX_HOME/auth.json` and `~/.gemini/oauth_creds.json`. The variable names must match the ones `crate::canon::PathVars` already binds. Check them in `canon.rs`, and if a variable is not bound there, add it the way `CODEX_HOME` was added.
- [ ] **Step 4: Run `cargo test --workspace --no-fail-fast`.** Expected: PASS.
- [ ] **Step 5: Strike the roadmap item** "agents' own credential files … are readable". Then commit with message `feat(secrets): deny reading the agents' own login tokens`.

---

### Task 5: Check here-document handling against real shells

The lexer ends a here-document inside `$(…)` at a line that starts with its delimiter and contains a `)`. That behavior was checked against bash 5.3 only. macOS CI runners ship `/bin/bash` 3.2 and `/bin/zsh`.

**Files:**
- Create: `crates/guard/tests/shell_differential.rs`

**Interfaces:**
- Consumes: `saiifeguard::Engine` with a single test pack that denies `^touch` (built as the corpus tests build packs).

- [ ] **Step 1: Write the test `heredoc_matches_installed_shells`.**
  - Shells: for each of `/bin/bash`, `/bin/sh`, `/bin/zsh`, `/usr/bin/zsh` and `bash` on PATH, if the file exists, run every case through `<shell> -c`. The working directory is a tempdir, and HOME and PATH stay as they are, which is safe here because `touch` only creates a marker in the tempdir.
  - Cases: at least 12 command lines in which a marker command `touch ran` sits either inside a here-document body or right after it. Include:
    - `x=$(cat <<EOF\ntouch ran\nEOF\n)`
    - `x=$(cat <<EOF\nhi\nEOF)\ntouch ran`
    - `x=$(cat <<'EOF'\na\nEOF )\ntouch ran`
    - quoted and dashed delimiters (`<<-EOF` with tabs)
    - two here-documents on one line
    - a here-document inside backticks
  - Check: for each shell and case, compare "the shell created `ran`" with "the engine denies the line". If they differ, fail with the shell path, its `--version` first line and the case.
  - If no shell is found, the test passes and prints `no shells found; skipped`.
- [ ] **Step 2: Run `cargo test -p saiife-guard --test shell_differential`** locally (bash 5.x). If a case differs on bash 5, the lexer is wrong for that case. Report it as DONE_WITH_CONCERNS, with the case, and do not change the lexer in this task.
- [ ] **Step 3: Commit** with message `test(guard): compare here-document handling with installed shells`.
- [ ] **Step 4: Push the branch** with `git push origin plan-5a-hardening` and read the macOS CI result for this test. If bash 3.2 or zsh differs, report it as DONE_WITH_CONCERNS with the CI log lines. The controller rules on it.

---

### Task 6: `status` is faster and names inactive rules

**Files:**
- Modify: `crates/cli/src/status_cmd.rs` (`last_calls`, `run`), `crates/audit/src/store.rs`
- Test: `crates/cli/tests/status_cmd.rs`, `crates/audit/src/store.rs` tests

**Interfaces:**
- Produces: `pub fn read_recent(dir: &Path, want: impl FnMut(&Record) -> bool) -> ReadResult` in `store.rs`. It reads the month files newest first and stops after the first file in which `want` has returned `false`, meaning "found all I need". It returns the records read so far and any `dir_error`.
- Consumes: `packs_cmd::inactive_summary(active: &[Pack], vars: &PathVars) -> String`.

- [ ] **Step 1: Write failing tests.**
  - `read_recent_stops_early` (store): a bad month file older than the stopping point is never opened, so its `unreadable_files` is not counted.
  - `status_reads_recent_months_only` (cli): seed 24 month files with 200 000 records in total by writing JSONL directly, plus one recent record for each hooked agent. `status` exits 0 within 1 s in a debug build and shows each agent's last call.
  - `status_names_inactive_path_rules`: unset `CODEX_HOME` and `CLAUDE_CONFIG_DIR`. `status` prints the `inactive here: $CODEX_HOME is not set: core.secrets, core.self` line from `inactive_summary`, below the packs line.
- [ ] **Step 2: Run the covering tests.** Expected: FAIL.
- [ ] **Step 3: Implement** `read_recent`, use it in `last_calls`, and print the inactive summary in `run`.
- [ ] **Step 4: Run `cargo test --workspace --no-fail-fast`.** Expected: PASS.
- [ ] **Step 5: Strike the roadmap items** "status performance" and "`status` does not yet show a note for them". Then commit with message `perf(status): read the newest audit files only; name inactive path rules`.

---

### Task 7: `status` / `init` UX fixes

These are from the plan-2 carry-over. Each one is a separate test in `crates/cli/tests/status_cmd.rs` or `init_cmd.rs`.

**Files:**
- Modify: `crates/cli/src/status_cmd.rs`, `crates/cli/src/init_cmd.rs`, `crates/agents/src/integrity.rs`
- Test: `crates/cli/tests/status_cmd.rs`, `crates/cli/tests/init_cmd.rs`

- [ ] **Step 1: Write failing tests**, one per behavior:
  - `status_in_subdir_after_config_removed`: `.saiife/config.toml` is deleted, and `status` runs from `src/`. It names the project root from the integrity record and says that `.saiife/config.toml` was removed. Exit code 1. Today it says "not set up".
  - `partial_off_keeps_record_for_failed_agent`: `init --off` with one agent config made unwritable. The integrity record keeps only the agent that failed, and a second `status` warns only about that agent.
  - `integrity_dir_is_tightened`: an existing integrity directory with mode 0755 becomes 0700 after `init`.
  - `dangling_agent_config_symlink_is_explained`: `.claude/settings.json` is a dangling symlink. `init` exits non-zero with a message that names the link and its missing target, not a raw I/O error.
  - `failed_agent_entry_clears_on_success`: an integrity record holds an error entry for codex. A later `saiife init --agent codex` that succeeds clears it, and `status` no longer warns.
  - `outside_symlink_off_gives_cleanup_hint`: `init --off` refuses a symlinked agent config that points outside the project. The refusal names the outside file and says to remove the saiife hook entry there by hand.
- [ ] **Step 2: Run the covering tests.** Expected: FAIL.
- [ ] **Step 3: Implement each behavior.** Use the existing `Problem` and warning style.
- [ ] **Step 4: Run `cargo test --workspace --no-fail-fast`.** Expected: PASS.
- [ ] **Step 5: Strike the matching "Status/init UX" roadmap lines.** Then commit with message `fix(status,init): clearer messages and records after partial or broken setups`.

---

### Task 8: Cut the per-call hook cost

A release-build `saiife check` currently takes about 34 ms for a Bash payload and 39 ms for a Read payload. It runs for every agent tool call. Target: at most 20 ms median for both, measured with `scripts/bench-check.sh` (created in this task) on the same machine.

**Files:**
- Create: `scripts/bench-check.sh`
- Modify: whatever the profile points at. The likely candidates are `crates/guard/src/builtins.rs` / `pack.rs` (all 13 packs are compiled at startup, inactive ones included) and `engine.rs` `bind_paths` (path rules bound eagerly).
- Test: `crates/cli/tests/check_project.rs`, guard unit tests

- [ ] **Step 1: Write `scripts/bench-check.sh`.** It builds the release binary and creates a tempdir project with temp HOME, data and audit dirs, then runs `saiife init --agent claude` there. It then times 50 `saiife check --hook-exit --agent claude` calls for each of a Bash payload (`git status && ls -la src`) and a Read payload (`README.md`), and prints `bash: N ms/call` and `read: N ms/call` (median). It removes the tempdir on exit. Record the numbers before the change in the report.
- [ ] **Step 2: Profile.** Use `perf` if it is available, or timing logs behind an env var removed before commit. Name the top costs in the report.
- [ ] **Step 3: Write `lazy_packs_keep_warnings`.** With a built-in pack whose TOML has a broken regex, injected the way the existing pack-warning tests do it, `check` still prints the pack warning on stderr and the decision is unchanged. Also confirm that an opt-in pack that is not active is never compiled. Use a counter or a test hook in `pack.rs`.
- [ ] **Step 4: Implement the cheapest changes that reach the target.** Compile only the active packs (default-on, plus project config, plus `--pack`), and bind path rules only when the payload needs them. The decisions in every existing test must stay unchanged.
- [ ] **Step 5: Run `scripts/bench-check.sh` and `cargo test --workspace --no-fail-fast`.** Expected: both medians are at most 20 ms and all tests pass. If the target is out of reach, report the best numbers reached and what still costs, as DONE_WITH_CONCERNS.
- [ ] **Step 6: Strike the roadmap item** "per-call fixed cost about 33 ms". Then commit with message `perf(check): compile only active packs and bind path rules lazily`.

---

### Task 9: Housekeeping

These are small items from the plan 1–4 carry-over lists, in one task, each with its own test.

**Files:** `crates/audit/src/store.rs`, `crates/cli/src/audit_cmd.rs`, `crates/cli/src/report.rs`, `crates/cli/src/report_html.rs`, `crates/guard/src/engine.rs`, `crates/cli/tests/check_audit.rs`, plus the roadmap.

- [ ] **Step 1: Write failing tests, then fix:**
  - `audit_dir_is_0700`: `append` creates the audit dir with mode 0700 (unix).
  - `since_overflow_is_an_error`: `--since 99999999999d` exits 2 with the usual `--since` message, not a panic. Use checked arithmetic.
  - `concurrent_checks_write_whole_lines`: change the existing test to read through `store::read_all` and assert `skipped_lines == 0`, so a disk-quota hit shows up as a skipped line rather than a UTF-8 panic.
  - `test_audit_dirs_are_cleaned`: no test leaves `/tmp/saiife-test-audit-*` behind. Switch those tests to `tempfile::tempdir()`.
  - `unjudgeable_reason_is_masked`: an Unjudgeable reason that holds a path with a token-shaped segment (`ghp_…`) is written masked. Apply `mask` to `reason` in `Record::at`, and update the doc comment in `record.rs` that says only `input` is masked.
  - Report polish:
    - the summary count tests assert `<dd>N</dd>`;
    - the order test matches `<h2>…</h2>`;
    - `Show all 1 decision` uses the singular;
    - empty projects or agents render `none`;
    - `h4` gets a CSS rule;
    - the "could not be read" note names the folder that holds the unreadable config;
    - a relative project string is treated like an empty one ("Unknown project folder; …");
    - the "{n} log files could not be read." string gets a test;
    - remove the print rule for closed `<details>`, since it has no effect.
  - Rename `audit_cmd::run`'s `report` parameter to `report_path`, and `since_arg`/`since` to `since_text`/`since_time`.
- [ ] **Step 2: Run `cargo test --workspace --no-fail-fast` and `scripts/test-offline.sh`.** Expected: PASS.
- [ ] **Step 3: Strike the matching roadmap lines.** Then commit with message `chore: plan 1–4 housekeeping (audit dir mode, --since overflow, masked reasons, report polish)`.
