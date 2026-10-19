# Plan 5b — Docs, demo and review clean-ups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the plan-5b review carry-over in code, write the v1 docs
(one page per pack, one per agent, threat coverage, Codex + Ollama recipe),
and ship a demo script plus a user-run live-check script for Codex and Gemini.

**Architecture:** Tasks 1–4 are small, independent code fixes in the
existing crates, each with its own tests. Tasks 5–6 add Markdown under
`docs/` and a test that pins the docs to the built-in packs, so a new pack
cannot ship without a page. Task 7 adds `scripts/demo.sh` (offline,
sandboxed, runs in CI) and `scripts/live-check-agents.sh` (run by the user,
never by CI or a subagent).

**Tech Stack:** Rust workspace (`guard`, `audit`, `agents`, `cli` crates),
Markdown, POSIX `sh`/bash scripts, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-13-saiife-cli-v1-design.md`
(§1.1, §7.3, §8, §10, §12). Carry-over items are in
`docs/superpowers/plans/2026-10-13-saiife-v1-roadmap.md` under
"Carry-over from plan 5a" and the "Plan 5 (docs …)" lines.

## Global Constraints

- No network calls at runtime or in tests; the offline CI job must stay green (spec §8).
- Tests point `HOME`, `PATH`, `SAIIFE_DATA_DIR` and `SAIIFE_AUDIT_DIR` at tempdirs. Never run `saiife init` against the real home or this repo.
- Scratch dirs go under `mktemp -d -p /home/jonas/projects/personal/saiife`, not `/tmp` (per-user quota).
- Docs language: plain English for a non-developer reader (DPO, team lead); short sentences; no marketing words.
- Every docs page that describes protection has a "Not covered" section (spec §1.1: "the docs state which threats a given setup does *not* cover").
- Stage explicit paths only (`git add <file>…`), never `git add -A`/`.`; never `git checkout` an older commit in the shared tree (use `git worktree add` under the scratch dir).
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. A built-in pack added later without a docs page — Task 5's `docs_pages` test must fail for it (it iterates `builtin_packs()`, not a hard-coded list).
2. A fresh install with no audit log — `status` must say "no call yet", not "no call in the last 12 months" (Task 3).
3. `demo.sh` run on a machine with a real `~/.claude` — it must not read or write the real home (Task 7 asserts `HOME` is a tempdir before anything else).
4. `live-check-agents.sh` run twice — it must clean up its temp project and leave no hook in any real config (Task 7).
5. The docs promising a block the engine does not make — Task 5's test checks every example the pages mark as blocked against `saiife check`-equivalent engine calls.

---

### Task 1: Guard engine and lexer clean-ups

**Files:**
- Modify: `crates/guard/src/engine.rs` (comments near lines 489 and 1584, `environment_phase`, `with_paths` doc at 181)
- Modify: `crates/guard/src/lexer.rs` (`_ =>` arms in operator and quote handling; merged `,`/`}` brace arm)
- Modify: `crates/guard/tests/refactor_equivalence.rs`
- Modify: `crates/guard/tests/cross_pack.rs`

**Interfaces:** no public signature changes, except `environment_phase` loses `&self` if it becomes an associated fn (private).

- [ ] **Step 1: Write the failing tests in `cross_pack.rs`**
  - `allow_in_one_pack_does_not_hide_deny_in_another`: pack A allows `^foo\b`, pack B denies `^foo\s+--bad`; `foo --bad` → Deny from pack B; `foo ok` → Allow.
  - `two_allowing_packs_return_first_trace`: packs A and B both allow `^foo`; the allow trace names pack A (load order).
  Build packs from TOML strings the way existing `cross_pack.rs` tests do.
- [ ] **Step 2: Run** `cargo test -p saiife-guard --test cross_pack` — the first should already pass (plan 5a behaviour; record that it passed at once in the report), the second fails or passes; either way keep both as regression pins.
- [ ] **Step 3: `refactor_equivalence.rs`** — replace the constant `CORPUS.len() >= 60` assert with an assert on the deny count matching a pinned number printed by the test, and compare denies by `(pack, pattern)` not pack alone.
- [ ] **Step 4: engine.rs** — rewrite the two "judged above/below" comments to name the phase methods that do the judging; drop the unused `&self` from `environment_phase`; fix the `with_paths` doc comment to say path rules are bound per call and the gain is compiling each glob once.
- [ ] **Step 5: lexer.rs** — replace the `_ =>` arms that rely on `step()` routing with explicit arms plus `unreachable!("routed by step()")`; split the merged `,`/`}` brace arm into two arms.
- [ ] **Step 6: Run** `cargo test -p saiife-guard` — all pass, `refactor_equivalence` and `shell_differential` unchanged in outcome.
- [ ] **Step 7: Commit** `refactor(guard): plan-5a review clean-ups; pin cross-pack allow scoping`

### Task 2: Shell differential test clean-ups

**Files:**
- Modify: `crates/guard/tests/shell_differential.rs`

- [ ] **Step 1:** Build the shell list and `cases()` once (e.g. a `OnceLock` or one call in the test fn passed down), not per shell.
- [ ] **Step 2:** Key `KNOWN_NON_BASH_OVER_DENIES` to the shell name only (drop the zsh version key) and assert, for every tolerated case, that the engine's verdict is Deny (over-deny direction), so a future engine change that turns one into an allow fails.
- [ ] **Step 3:** Spawn each shell with `HOME` set to a tempdir, `BASH_ENV` and `ENV` removed, and `ZDOTDIR` set to the tempdir, so startup files never run from the real home.
- [ ] **Step 4:** Collapse the collapsible `else { if … }` (clippy `collapsible_else_if`).
- [ ] **Step 5: Run** `cargo test -p saiife-guard --test shell_differential` and `cargo clippy -p saiife-guard --tests -- -D warnings` — pass (shells not installed are skipped as before).
- [ ] **Step 6: Commit** `test(guard): shell differential runs each shell with a temp HOME`

### Task 3: Status and audit fixes

**Files:**
- Modify: `crates/audit/src/store.rs` (`read_recent`, its tests)
- Modify: `crates/cli/src/status_cmd.rs` (line ~144 wording; `status_root` at ~245; outside-symlink `--off` wording at ~97)
- Test: `crates/cli/tests/status_cmd.rs`, `crates/cli/tests/packs_cmd.rs`

**Interfaces:**
- `ReadResult` gains `pub cut_short: bool` — true only when `read_recent` stopped because it hit `max_files` with files left unread. `status` uses it.

- [ ] **Step 1: Failing tests**
  - `status_cmd.rs::fresh_install_says_no_call_yet`: init a temp project, no audit records → status line for the agent contains `no call yet` and not `12 months`.
  - `status_cmd.rs::old_log_says_last_12_months`: 13 month files with records only in the oldest → `no call in the last 12 months`.
  - `store.rs::read_recent_with_no_wanted_records_short_circuits`: when `want` is never satisfied because the caller wants nothing (pass a closure and a `max_files` of 12 with 3 empty month files), `read_recent` reads the files that exist and `cut_short == false`. Also: an empty month file must not keep `more = true`.
  - `packs_cmd.rs::explain_prints_inactive_note`: run the binary `saiife packs core.self` with `SAIIFE_AUDIT_DIR` unset → output contains `(inactive here: $SAIIFE_AUDIT_DIR is not set)`.
  - `status_cmd.rs::nearer_project_with_removed_config_is_named`: parent dir has `.saiife/config.toml`, child dir had one that was removed but still has `.saiife/` → status from the child names the child's removed config, not the parent project.
- [ ] **Step 2: Run** the tests — they fail.
- [ ] **Step 3: Implement** `cut_short`; `status` prints `no call yet` when not cut short, `no call in the last {SCAN_MONTHS} months` when cut short; `status_root` stops at the first ancestor holding a `.saiife/` directory; hoist `ts` in the `read_recent` test.
- [ ] **Step 4:** Outside-symlink wording (roadmap "Plan 5b (status wording)"): when the integrity record shows the agent's earlier `init` failed, the `--off` message says the hook "may still be in place" and names the outside file to check by hand, instead of "is still in place".
- [ ] **Step 5: Run** `cargo test -p saiife-audit -p saiife` — pass.
- [ ] **Step 6: Commit** `fix(status): "no call yet" on fresh installs; nearer project wins`

### Task 4: Init and housekeeping fixes

**Files:**
- Modify: `crates/cli/src/init_cmd.rs` or `crates/agents/src/integrity.rs` (symlink chain error), `crates/audit/src/store.rs` (dir mode), `crates/cli/src/audit_cmd.rs` (`--since` text at lines 20 and 155), `crates/audit/src/record.rs` (tests), `crates/guard/src/builtins.rs` (warning text at 128)

- [ ] **Step 1: Failing tests**
  - `dangling_symlink_chain_names_last_link`: `a -> b -> missing` as the agent config → the error names `missing` (the dangling end), not `b`.
  - `existing_loose_audit_dir_is_tightened`: create the audit dir at 0755, write one record → mode is 0700.
  - `ordinary_path_in_reason_stays_unmasked`: a reason `cannot resolve /home/u/project/src/main.rs` survives `Record::at` unchanged.
  - `record_size_check_measures_serialized_line`: the 16 KB cap is checked on the bytes written to the log line (existing behaviour may already hold; pin it).
  - `builtins.rs`: a pack with a valid `[pack]` header and a broken rule is warned as `built-in pack has a broken rule: …`, not `failed to load`.
- [ ] **Step 2: Run** — they fail where behaviour changes.
- [ ] **Step 3: Implement**: follow the symlink chain to its last link for the error; `create_dir_all` then `set_permissions(0o700)` when the existing mode is looser (unix only, `#[cfg(unix)]`); one `fn since_error(s: &str) -> String` used by both `--since` call sites; the new warning wording. Add `#[cfg(unix)]` on unix-only test code you touch.
- [ ] **Step 4: Run** `cargo test --workspace` — pass.
- [ ] **Step 5: Commit** `fix: symlink-chain errors, audit dir mode, --since text, pack warning wording`

### Task 5: Pack docs pages and the docs test

**Files:**
- Create: `docs/packs/<id>.md` for each of the 13 built-in packs (`core.filesystem`, `core.git`, `core.secrets`, `core.self`, `cloud.aws`, `cloud.azure`, `cloud.gcloud`, `container.docker`, `container.k8s`, `db.mongo`, `db.mysql`, `db.postgres`, `iac.terraform`)
- Create: `docs/packs/README.md` (index table: id, on by default?, one line)
- Create: `crates/guard/tests/docs_pages.rs`

**Page shape (every page, these headings in this order):** `# <pack name> (<id>)`, one-paragraph summary, `## On by default` (yes/no and how to turn on/off in `.saiife/config.toml`), `## Blocked`, `## Allowed on purpose`, `## Not covered`, `## Examples`.
- `## Examples` holds a fenced block with info string `saiife-examples`, one line per example: `deny <command>` or `allow <command>`.
- Content comes from the pack TOML (each rule's `reason`) and, for `core.secrets` and `core.self`, from the roadmap's "Plan 5 (docs, `core.secrets` page)", "Plan 5 (docs, `core.self` page)", "Plan 5b (docs, `core.secrets` and paths)", "Plan 5 (docs, from the final wave)" and "Plan 5b (docs, known over-denies)" lines — every stated limit there goes in `## Not covered`.

- [ ] **Step 1: Write `docs_pages.rs`** with:
  - `every_builtin_pack_has_a_page`: for each pack from `builtin_packs()`, `docs/packs/<id>.md` exists and contains the five `##` headings above, in order.
  - `examples_match_the_engine`: parse every `saiife-examples` block; for each line, evaluate the command with only that pack active (the same engine entry point `corpus_*.rs` tests use) and assert deny/allow matches. Each page has at least 3 deny and 1 allow example.
  - `index_lists_every_pack`: `docs/packs/README.md` mentions every pack id.
- [ ] **Step 2: Run** `cargo test -p saiife-guard --test docs_pages` — fails (no pages).
- [ ] **Step 3: Write the 13 pages and the index.**
- [ ] **Step 4: Run** the test — passes.
- [ ] **Step 5: Commit** `docs: one page per built-in pack, pinned by a test`

### Task 6: Agent pages, threat coverage, Codex + Ollama recipe, README

**Files:**
- Create: `docs/agents/claude-code.md`, `docs/agents/codex.md`, `docs/agents/gemini.md`
- Create: `docs/threats.md`
- Create: `docs/recipes/codex-ollama.md`
- Modify: `README.md`
- Modify: `crates/guard/tests/docs_pages.rs` (one more test)

**Content:**
- Agent pages: what `saiife init` writes (file and entry, from `crates/agents/src/{claude,codex,gemini}.rs`), which tools are judged, `init --off`, what `status` checks, and a `## Not covered` / `## Not yet verified live` section from the roadmap lines "Plan 5 (verify live …)", "(Gemini, verify live + docs …)", "(Gemini status …)", "(Codex status …)", "(check)". Codex page notes the `/hooks` trust step; Gemini page notes the exit-127 question.
- `docs/threats.md`: the §1.1 table, then per setup (v1 with a human nearby; v1 on auto mode/unattended) which threats are covered, partly covered, not covered (spec §12.9), linking to `docs/packs/core.self.md` and `core.secrets.md`.
- Recipe: Codex CLI against a local Ollama model (`~/.codex/config.toml` provider block with `base_url = "http://localhost:11434/v1"`), then `saiife init` in the project; mark it "manual verification pending (plan 5c)" at the top.
- README: what saiife is (2 lines), install placeholder pointing at releases ("first release pending"), 4-command quickstart (`saiife init`, `saiife status`, `saiife audit`, `saiife audit --report report.html`), links to `docs/threats.md`, `docs/packs/`, `docs/agents/`; keep the License section.

- [ ] **Step 1: Add test** `docs_links_resolve`: every relative Markdown link in `README.md` and `docs/**/*.md` (excluding `docs/superpowers/`) points at an existing file.
- [ ] **Step 2: Run** — fails (pages missing).
- [ ] **Step 3: Write the pages and README.**
- [ ] **Step 4: Run** `cargo test -p saiife-guard --test docs_pages` — passes.
- [ ] **Step 5: Commit** `docs: agent pages, threat coverage, Codex + Ollama recipe, README quickstart`

### Task 7: Demo script and live-check script

**Files:**
- Create: `scripts/demo.sh`
- Create: `scripts/live-check-agents.sh`
- Create: `docs/demo.md`
- Modify: `.github/workflows/*.yml` (add a `demo` step to the existing Linux test job, offline-compatible)

**demo.sh** (bash, `set -euo pipefail`):
1. First thing: create a sandbox with `mktemp -d`, export `HOME`, `SAIIFE_DATA_DIR`, `SAIIFE_AUDIT_DIR` into it, and abort if `HOME` is not under the sandbox. `trap` removes the sandbox unless `KEEP=1`.
2. Build (`cargo build --release -q`) unless `SAIIFE_BIN` is set; put the binary first on `PATH`.
3. Create a project in the sandbox with a `.env`, run `saiife init --agent claude` (non-interactive form the CLI already has), print `saiife status`.
4. Feed three recorded Claude `PreToolUse` payloads to `saiife check --agent claude` (Bash `rm -rf ~`, Read `.env`, Bash `saiife init --off`), printing each verdict line; reuse the shape of `crates/cli/tests/fixtures/claude/`.
5. `saiife audit`, then `saiife audit --report "$sandbox/report.html"`; print the path.
6. Exit 0 only if all three were blocked (exit code 2 from `check`) and the report exists. Total runtime under 3 minutes (spec §12.6).

**live-check-agents.sh**: run by the user, not CI. For each of `codex` and `gemini` found on `PATH`: make a temp project under `$HOME/.cache/saiife-live`, `saiife init --agent <a>`, run the agent non-interactively with a prompt asking it to `cat .env` and to run `saiife init --off`, then grep the audit log for both denies, print PASS/FAIL per item, record the agent version, run `saiife init --off`, delete the temp project. Missing agent → `SKIP <agent>: not installed`. Writes the summary to `$HOME/.cache/saiife-live/result.txt`. Uses a temp `SAIIFE_AUDIT_DIR`; uses the real HOME only for the agent's own login (never copies credentials).

`docs/demo.md`: how to run `scripts/demo.sh`, the expected output (three `blocked` lines), and that it never touches the real home.

- [ ] **Step 1:** Write `demo.sh`; run `bash scripts/demo.sh` — exits 0, prints three blocked verdicts and the report path.
- [ ] **Step 2:** Run it under `scripts/test-offline.sh`'s network-less wrapper (or `unshare -rn bash scripts/demo.sh` with a prebuilt `SAIIFE_BIN`) — exits 0.
- [ ] **Step 3:** Add the CI step `bash scripts/demo.sh` (with `SAIIFE_BIN` set to the job's release build) to the Linux test job.
- [ ] **Step 4:** Write `live-check-agents.sh` and `docs/demo.md`; run `bash -n` on both scripts and `shellcheck` if installed. Do **not** run `live-check-agents.sh` (it needs the user's agent logins).
- [ ] **Step 5: Commit** `feat: demo script (runs in CI) and user-run live check for Codex and Gemini`

---

## After the plan (controller, not a task)

- Update the roadmap: strike the carry-over items closed here; move "live Codex/Gemini run", "Codex + Ollama manual verification" and "report at phone width / print preview" to a "Plan 5c / user checks" list.
- Hand the user `scripts/live-check-agents.sh` and the by-eye report check as one short instruction.
