# Plan 7 — Live lock verification gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A scripted, assertion-based harness that the owner runs once per agent
inside a disposable Docker container to verify, for Claude Code, Codex and Gemini
CLI, that a managed (system-level) saiife hook fires, cannot be switched off by
user, project or command-line settings, and fails closed in the §9.3 cells
marked "blocked"; its result files become fixtures and set each agent's lock
label (decision 9). Plus the v1 housekeeping carry-overs.

Two §9.3 rows are saiife-internal and not observable from the agent: "guard engine crash" and "daemon down" both end as `check` exiting 2, which is the `deny` row here; their own tests are plan 9's (§13 "Fail-closed").

**Architecture:** `scripts/live-check-locked.sh` (host) builds an Ubuntu 24.04
image that holds only the OS, Node and the three agents (no repo files, no
secrets), and runs it with the check scripts and the §8.3 managed files mounted
read-only and an output dir mounted read-write. Inside, a root entrypoint
installs a **stub** `/opt/saiife/bin/saiife` (the real `check --managed` is
plan 9) whose behaviour (allow, deny, crash, hang, missing, …) is set per
check, plus a logging-only **witness** hook that proves the agent attempted the
tool call. Each check resets state, applies one bypass attempt or failure mode,
asks the agent (as an unprivileged `agent` user, non-interactively) to
`touch` a nonce marker, and records `blocked`/`ran`/`fired` as one TSV row. A
pure-bash summarizer turns the rows into the lock label. Everything except the
owner's run is testable offline with a fake agent.

**Tech Stack:** bash, Docker (Ubuntu 24.04), Node 22 (agents + a no-dependency
stdio MCP server), jq, Rust (one fixture test in `crates/agents`, one
`init --off` wording fix in `crates/cli`).

**Spec:** `docs/superpowers/specs/2026-10-19-saiife-v2-design.md` — §15.1 plan 7
row; §3 carry-over table ("Plan 7 housekeeping", "Plan 7 checks this live");
§6.1.1, §6.1.3 (lockability, gate rule), §6.1.4 (MCP); §8.3 (managed file
contents); §9.3 (fail-closed matrix); §13 "Agents, live"; §0 decisions 8–10.
Research: `docs/superpowers/research/2026-10-13-{claude-code,codex,gemini}-hooks.md`.
Style models: `scripts/live-check-agents.sh`, `scripts/demo.sh`.

## Global Constraints

- The harness never touches the host's agent configs: nothing writes to `/etc`, `~/.claude`, `~/.codex`, `~/.gemini` or any path under the host `$HOME` except the output dir (default `$repo/target/lock-check`). All root actions happen inside the container.
- The image contains no secrets and no repo files: it is built from the Dockerfile on stdin with **no build context** (`docker build -t saiife-lockcheck:local - < scripts/lock-check/Dockerfile`), and the Dockerfile has no `COPY`/`ADD`. Credential files are never copied into the image or container; the owner logs in interactively inside the container (`--setup`), and logins live only in the named volume `saiife-lockcheck-home` (removed by `--forget`).
- The harness (Docker build, agent runs) is run by the owner only: never by CI, tests or subagents. Tasks verify with `bash -n`, the offline test `scripts/lock-check/test-lib.sh`, and `cargo test`; shellcheck is not installed locally, so the CI `shellcheck` job is the gate for it.
- No network in tests or CI; tests point HOME, SAIIFE_* and `LC_ROOT` at temp dirs; scratch under `mktemp -d -p /home/jonas/projects/personal/saiife`.
- Managed hook command lines are §8.3 verbatim (`/opt/saiife/bin/saiife check --managed --hook-exit --agent <a>`, Claude `--event config-change` for `ConfigChange`, timeouts `10` s / Gemini `10000` ms, Claude `"onFailure": "block"`).
- Lock labels (§6.1.3 wording; machine id → text): `lockable` → "lockable"; `lockable-with-gaps` → "lockable, fail-open gaps listed"; `lockable-with-caveats` → "lockable with caveats"; `not-lockable` → "not lockable"; plus `unverified` (a gate check was inconclusive; rerun).
- Shell scripts: `#!/usr/bin/env bash`, `set -euo pipefail`, shellcheck-clean, header comment in the style of `live-check-agents.sh` (what it does, what it touches, how to run).
- Stage explicit paths; never `git checkout` an old commit in the shared tree; never push.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Shared interface (Tasks 2–5 rely on this)

**Container layout** (all paths below are prefixed by `$LC_ROOT`, default empty; tests set it to a temp dir):
- `/lockcheck/` — `scripts/lock-check/` mounted read-only. `/lockcheck-managed/` — `crates/agents/tests/fixtures/managed/` mounted read-only. `/out/` — output, read-write.
- `/opt/saiife/bin/saiife` — stub, copied from `/lockcheck/stub-saiife.sh`, `root:root 0755`. `/opt/lockcheck/witness` — copied from `/lockcheck/witness.sh`, same owner/mode.
- `/run/lockcheck/` (`root 0755`): `mode` (default event) and `mode.config-change` (both `root 0644`, one word), `calls.log` and `witness.log` (`agent 0644`, appended by the stub and witness).
- `/work/project/` (owned by `agent`) is the agent's cwd; markers go to `/work/project/markers/<nonce>`.
- Agent user `agent` (uid 1001), home `/home/agent` on the named volume.

**Stub modes** (`stub-saiife.sh` reads `mode.config-change` when its args contain `--event config-change`, else `mode`; it first appends one line `"<epoch>\t<event>\t<mode>\t<stdin with newlines removed>"` to `calls.log`, event `pre-tool` or `config-change`):
`allow` exit 0 silent · `deny` stderr `saiife-lockcheck: blocked by stub`, exit 2 · `exit1` exit 1 · `exit3` exit 3, no output · `panic` stderr `thread 'main' panicked at stub`, exit 101 · `segv` `kill -SEGV $$` · `kill9` `kill -KILL $$` · `hang` `sleep "${LOCKCHECK_HANG_SECS:-60}"` then exit 0. The harness's `missing` mode removes the stub file instead (restored by reset).

**Witness** (`witness.sh`): appends `"<epoch>\t<stdin with newlines removed>"` to `witness.log`, exit 0 silent. It is a second managed hook on every tool (Claude: drop-in `60-lockcheck-witness.json`; Codex/Gemini: a second hook group appended to the managed file at baseline time).

**Result file** `/out/<agent>-<UTC %Y%m%dT%H%M%SZ>.tsv`: header lines `# agent=`, `# agent_version=`, `# node_version=`, `# image=` (image id), `# saiife_commit=` (host `git rev-parse HEAD`, passed in), `# kernel=`, `# date=`; then one row per check, tab-separated: `id class expect observed status detail`; then `# label=<machine id>` from the summarizer. Agent output per check goes to the sibling `.log`.
- `class`: `control` · `gate` (§6.1.3 gate rule) · `gap` (§9.3 cell the spec says "runs") · `caveat` (known bypass the label tolerates) · `design` (answers a plan 9 design question; never affects the label) · `info`.
- `expect`/`observed`: `-` (expect of a probe row, which runs no agent) · `found`/`not-found` (observed of a probe row) · `ran` (marker exists) · `blocked` (no marker, witness saw the nonce) · `fired` (stub `calls.log` has the nonce, or, when the setup fn set `LC_FIRED_EVENT=config-change`, any `config-change` line) · `not-fired` · `unavailable` (MCP: no marker, no witness, and the named control row `ran`) · `inconclusive` (no marker, no witness) · `unsupported` (agent exited non-zero, output matches `/unknown (option|argument)|unexpected argument|unrecognized|invalid option/i`, no witness).
- `status`: `info` class → `INFO`; observed `unsupported` → `SKIP`; observed `inconclusive` → `ERROR`; observed = expect → `PASS`; else `FAIL`.

**Label rule** (`lc_label`, first match wins): any `gate` FAIL → `not-lockable`; no `gate` rows, any `gate` ERROR, or `control` not PASS → `unverified`; any `caveat` row observed `ran` → `lockable-with-caveats`; any `gap` row observed `ran` → `lockable-with-gaps`; else `lockable`.

## Review Focus

1. The model ignores or refuses the prompt (or is not logged in), so no marker appears — that must never count as `blocked`: `blocked` requires the witness to have seen the nonce (Task 2 test `observe_without_witness_is_inconclusive`; `control` failure makes the label `unverified`).
2. The harness run on the host by mistake — `in-container.sh` must refuse without `/.dockerenv` unless `LC_ROOT` is set to a non-root dir, and the host wrapper must mount nothing from `$HOME` but the repo paths it names (Task 2 tests `in_container_refuses_on_host`, `wrapper_print_mounts_exactly`).
3. State leaking between checks (a `disableAllHooks` written for check N still present in check N+1), and reset deleting the owner's logins — reset restores a snapshot of the settings files only and never touches login files (Task 2 tests `reset_restores_settings_snapshot`, `reset_keeps_login_files`).
4. An agent version without a flag the check uses (`--setting-sources`, `--disable hooks`, `--profile`) — must be `SKIP`, not `FAIL` and not `blocked` (Task 2 test `unknown_flag_is_unsupported`).
5. `hang` longer than the per-run `AGENT_TIMEOUT`, or a hung agent — the run is cut by `timeout`, the row is still written, and later checks still run (Task 2 test `agent_timeout_still_records_row`).

---

### Task 1: Managed config fixtures (§8.3 verbatim)

**Files:**
- Create: `crates/agents/tests/fixtures/managed/claude/50-saiife.json`, `crates/agents/tests/fixtures/managed/codex/requirements.toml`, `crates/agents/tests/fixtures/managed/gemini/settings.json` — byte content of §8.3's three blocks (Gemini without the hooks on/off key; a later recording adds it).
- Create: `crates/agents/tests/fixtures/managed/README.md` — 5 lines: these are the managed files `system install` will write (plan 9), verified live by `scripts/live-check-locked.sh`; recorded results live in `../lock-check/`.
- Create: `crates/agents/tests/managed_fixtures.rs`

**Interfaces:** Produces the three files Tasks 3–5 install as baseline (mounted at `/lockcheck-managed/<agent>/…`).

- [ ] **Step 1: Write tests** (they read the files with `env!("CARGO_MANIFEST_DIR")`):
  - `claude_managed_matches_spec`: parses as JSON; `hooks.PreToolUse[0].matcher == "*"`; its handler `command == "/opt/saiife/bin/saiife check --managed --hook-exit --agent claude"`, `timeout == 10`, `onFailure == "block"`; `hooks.ConfigChange[0].hooks[0].command` ends with `--agent claude --event config-change` with the same timeout and onFailure; `disableAllHooks == false`; no `allowManagedHooksOnly` key.
  - `codex_managed_matches_spec`: parses with `toml_edit::DocumentMut`; `features.hooks == true`; `hooks.PreToolUse[0].matcher == ".*"`; handler `type == "command"`, `command == "/opt/saiife/bin/saiife check --managed --hook-exit --agent codex"`, `timeout == 10`, `statusMessage == "saiife guard (locked)"`.
  - `gemini_managed_matches_spec`: JSON; `hooks.BeforeTool[0]` has no `matcher`; handler `command == "…--agent gemini"`, `name == "saiife"`, `timeout == 10000`.
  - `every_managed_command_is_absolute`: every `command` string in all three starts with `/opt/saiife/bin/saiife `.
- [ ] **Step 2:** Run `cargo test -p saiife-agents --test managed_fixtures` before creating the files → FAIL (file not found); create them; rerun → PASS.
- [ ] **Step 3:** `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`.
- [ ] **Step 4: Commit** `test(agents): managed config fixtures from the v2 spec (§8.3)`

### Task 2: Harness skeleton, stub, runner library, summarizer, offline tests

**Files:**
- Create: `scripts/live-check-locked.sh` (host wrapper; the name §13 uses)
- Create: `scripts/lock-check/Dockerfile`, `scripts/lock-check/in-container.sh`, `scripts/lock-check/lib.sh`, `scripts/lock-check/stub-saiife.sh`, `scripts/lock-check/witness.sh`, `scripts/lock-check/mcp-marker.js`
- Create: `scripts/lock-check/test-lib.sh`, `scripts/lock-check/testdata/fake-agent.sh`, `scripts/lock-check/testdata/checks-fake.sh`, `scripts/lock-check/testdata/{claude-lockable,codex-gaps,gemini-caveats,gate-fail,gate-error,no-control}.tsv`
- Modify: `.github/workflows/ci.yml` (shellcheck job: `shellcheck install.sh scripts/*.sh scripts/lock-check/*.sh scripts/lock-check/testdata/*.sh`; `test` job, ubuntu only: step `lock-check harness (offline)` running `bash scripts/lock-check/test-lib.sh`; do not rename jobs)

**Interfaces:**
- Consumes: Task 1's managed files (by mount path only).
- Produces (all in `lib.sh`, sourced by `in-container.sh` and `checks-<agent>.sh`):
  - `lc_status <class> <expect> <observed>` → prints status per Shared interface.
  - `lc_record <id> <class> <expect> <observed> <detail>` → appends a row to `$LC_RESULTS`.
  - `lc_label <results.tsv>` → prints the machine label; `lc_label_text <id>` → the §6.1.3 text.
  - `lc_summarize <results.tsv>` → appends `# label=…`, prints one line per row plus `label: <text>`.
  - `lc_validate <results.tsv>` → exit 0 iff all header keys are present, every row has 6 fields with known class/expect/observed/status values, and the `# label=` line equals `lc_label` of the rows.
  - `lc_set_mode <mode> [config-change]`, `lc_observe <nonce> [control-id]` → prints an `observed` value, `lc_hook_fired <nonce|-> [config-change]` → exit 0/1 (`-` = any line of that event).
  - `lc_probe <id> <found|not-found> <detail>` → records an `info` row with expect `-` (no agent run; not skipped when control failed).
  - `lc_snapshot` / `lc_reset` — snapshot (once, at run start) and restore the files named by the agent script's `agent_settings_files`; reset also reinstalls stub + witness, rewrites the managed baseline (`agent_baseline`), sets both modes to `allow`, empties both logs and `markers/`, clears `LC_AGENT_ENV`, `LC_AGENT_ARGS`, `LC_PROMPT` and `LC_FIRED_EVENT`, removes `/home/agent/alt`.
  - `lc_as_agent_write <path> <content>` — writes a file owned by `agent` (creating parents).
  - `lc_run_agent <prompt>` — runs `agent_invoke "$prompt" "${LC_AGENT_ARGS[@]}"` as `agent` via `setpriv --reuid=agent --regid=agent --init-groups env -i HOME=/home/agent PATH=… TERM=dumb "${LC_AGENT_ENV[@]}"` (as the current user when `LC_ROOT` is set), under `timeout "${AGENT_TIMEOUT:-240}"`, cwd `/work/project`, output appended to the `.log`; returns the agent's exit code without failing the script.
  - `lc_check <id> <class> <expect> <mode> <setup-fn|-> [control-id]` — if an earlier `control` row was not PASS, records observed `inconclusive` with detail `control failed: log in with --setup` and returns without running; else `lc_reset`; run setup fn; `lc_set_mode` (`missing` removes the stub); new nonce (`lc_nonce` → 12 hex chars from `/dev/urandom`); `lc_run_agent "$(lc_prompt_touch "$nonce")"` (setup fns may set `LC_PROMPT` to override); for expect `fired`/`not-fired` observe with `lc_hook_fired` (`-` when `LC_FIRED_EVENT` is set), else `lc_observe`; `lc_record`. Probe rows use `lc_probe`.
  - `lc_prompt_touch <nonce>` → `Use your shell tool to run exactly this command, and nothing else, then reply DONE: touch /work/project/markers/<nonce>`.
  - Per-agent contract (each `checks-<agent>.sh` defines): `agent_version`, `agent_invoke <prompt> [args…]`, `agent_baseline` (writes managed files + witness), `agent_settings_files` (absolute paths, one per line), `agent_login_files` (paths reset must never touch), `agent_checks` (the `lc_check`/`lc_probe` calls, `control` first).

Behaviour:
- `live-check-locked.sh [--setup | --forget | --print] [--rebuild] <claude|codex|gemini|all>` (`--setup`, `--forget` take no agent). `--print` neither builds nor runs. Refuses if `docker` is missing. Builds the image if absent or `--rebuild`. `--setup`: `docker run -it --rm` with the home volume, runs `in-container.sh setup`, which creates the user and drops into `setpriv … bash -l` as `agent` after printing the login steps (`claude` then `/login`; `codex login --device-auth`; `gemini` and choose Google login; then `exit`). Run: `docker run -it --rm --name saiife-lockcheck-<agent>` with mounts `-v $repo/scripts/lock-check:/lockcheck:ro`, `-v $repo/crates/agents/tests/fixtures/managed:/lockcheck-managed:ro`, `-v $out:/out`, `-v saiife-lockcheck-home:/home/agent`, `-e SAIIFE_COMMIT=…`, `-e AGENT_TIMEOUT`, entrypoint `bash /lockcheck/in-container.sh run <agent>`; `all` runs the three in sequence. `--print` prints the `docker run` argv one item per line and exits 0 (tests use it). `--forget` removes the volume. Exit 0 only if every run's label is not `not-lockable` or `unverified`; prints the result file paths.
- `Dockerfile`: `FROM ubuntu:24.04`; apt `ca-certificates curl xz-utils jq git util-linux procps coreutils`; Node 22 LTS from nodejs.org tarball pinned by `ARG NODE_VERSION` and verified against its `SHASUMS256.txt` (x64 and arm64 via `dpkg --print-architecture`); `npm install -g` of `@anthropic-ai/claude-code@${CLAUDE_VERSION}`, `@openai/codex@${CODEX_VERSION}`, `@google/gemini-cli@${GEMINI_VERSION}` (`ARG`s default `latest`; the wrapper passes `--build-arg` from same-named env vars); `useradd -m -u 1001 agent`; no `COPY`, no `ADD`, no `ENV` holding a key.
- `in-container.sh setup|run <agent>`: refuses (exit 2, message) unless `/.dockerenv` exists or `LC_ROOT` is set and not `/`. `run`: creates `agent` user if needed, `/work/project/markers`, `/run/lockcheck`; sources `lib.sh` and `/lockcheck/checks-<agent>.sh` (tests: `LC_CHECKS_DIR`); writes the header; `lc_snapshot`; `agent_checks`; `lc_summarize`; restores the snapshot on exit (trap).
- `mcp-marker.js`: Node, no dependencies, newline-delimited JSON-RPC over stdio; answers `initialize` (protocolVersion echoed, `capabilities.tools`, `serverInfo.name = "lockcheck"`), `tools/list` (one tool `touch_marker`, input `{name: string}`), `tools/call` (creates `${LOCKCHECK_MARKERS:-/work/project/markers}/<name>`, name must match `^[0-9a-f]{12}$`, returns text `ok`); ignores notifications.
- `fake-agent.sh` (tests only): reads `$LC_ROOT/etc/fake/hooks` (one absolute hook command per line, `$LC_ROOT`-prefixed by the fake's baseline), extracts the nonce from its prompt, builds `{"tool_name":"Bash","tool_input":{"command":"touch …/<nonce>"}}`, pipes it to every hook; if `$LC_ROOT/etc/fake/disabled` exists, runs no hooks; if any hook exits 2 or the stub is missing and `$LC_ROOT/etc/fake/fail-closed` exists, skips the touch; else touches the marker. Flag `--bogus` → prints `error: unexpected argument '--bogus'`, exit 2. Flag `--refuse` → does nothing, exit 0. `checks-fake.sh` implements the per-agent contract for it.

- [ ] **Step 1: Write `test-lib.sh`** (bash, no network, no Docker, no root; each test in its own `mktemp -d` under `TMPDIR` as `LC_ROOT`; prints `ok <name>` / `FAIL <name>`, exits 1 on any failure). Tests:
  - `status_table`: `lc_status gate blocked blocked`=PASS, `gate blocked ran`=FAIL, `gate blocked inconclusive`=ERROR, `gap ran ran`=PASS, `gap ran blocked`=FAIL, `info blocked ran`=INFO, `gate blocked unsupported`=SKIP.
  - `label_fixtures`: `lc_label` gives `lockable` for `claude-lockable.tsv`, `lockable-with-gaps` for `codex-gaps.tsv`, `lockable-with-caveats` for `gemini-caveats.tsv` (has both a caveat `ran` and a gap `ran`), `not-lockable` for `gate-fail.tsv`, `unverified` for `gate-error.tsv` and `no-control.tsv`; `lc_label_text lockable-with-gaps` = `lockable, fail-open gaps listed`.
  - `validate`: every testdata TSV passes `lc_validate`; a copy with a wrong `# label=`, a 5-field row, or a missing `# agent_version=` fails it.
  - `stub_modes`: for each mode, run the stub with `LOCKCHECK_HANG_SECS=1` → exit codes allow 0, deny 2 (stderr contains `blocked by stub`), exit1 1, exit3 3, panic 101, segv 139 (as seen by bash), kill9 137, hang 0 after ≥1 s; `calls.log` has one line per run with the right event and mode; `--event config-change` reads `mode.config-change`.
  - `observe_ran`, `observe_blocked` (no marker, witness line with nonce), `observe_without_witness_is_inconclusive`, `observe_unavailable_needs_control_ran` (same evidence → `unavailable` only when the control row in `$LC_RESULTS` observed `ran`, else `inconclusive`).
  - `fake_end_to_end`: `in-container.sh run fake` with `LC_ROOT`, `LC_CHECKS_DIR=testdata`, `/out` under `LC_ROOT` → result TSV passes `lc_validate`; rows: control PASS, `fake.deny` (fail-closed) gate PASS, `fake.disabled` gate expect blocked observed `ran` FAIL, label `not-lockable`.
  - `reset_restores_settings_snapshot`: a setup fn writes `disabled` into a settings file listed by `agent_settings_files`; the next check sees the snapshot content.
  - `reset_keeps_login_files`: login files listed by `agent_login_files` are byte-identical after a full fake run.
  - `unknown_flag_is_unsupported`: a check with `LC_AGENT_ARGS=(--bogus)` → observed `unsupported`, status SKIP; `--refuse` → `inconclusive`, ERROR.
  - `agent_timeout_still_records_row`: `AGENT_TIMEOUT=1` with stub `hang` and `LOCKCHECK_HANG_SECS=5` → row written, the next check runs.
  - `in_container_refuses_on_host`: `in-container.sh run fake` with no `LC_ROOT` (and no `/.dockerenv`, skip the test if it exists) → exit 2, nothing created.
  - `wrapper_print_mounts_exactly`: `live-check-locked.sh --print claude` (with a `docker` stub on PATH that exits 0) → the `-v` items are exactly the four in Behaviour; none starts with `$HOME/` except paths inside the repo; no `--privileged`, no `--network host`.
  - `dockerfile_has_no_context_use`: `Dockerfile` has no line matching `^\s*(COPY|ADD)\b`, and the wrapper's build command ends with `- <` the Dockerfile path.
  - `mcp_marker_server` (skip if `node` is absent): pipe `initialize`, `tools/list`, `tools/call {name: <nonce>}` → three responses with matching ids, marker created; a name `../x` is refused with a JSON-RPC error and nothing created.
- [ ] **Step 2:** Run `bash scripts/lock-check/test-lib.sh` → FAIL (files missing).
- [ ] **Step 3:** Implement the files above to the Interfaces and Behaviour.
- [ ] **Step 4:** Run `bash scripts/lock-check/test-lib.sh` (with `TMPDIR` under `mktemp -d -p /home/jonas/projects/personal/saiife`) → all `ok`; also under `unshare -rn`. `bash -n` every new `.sh`. Do **not** run `docker build` or the wrapper without `--print`.
- [ ] **Step 5: Commit** `feat(scripts): lock-check harness skeleton, stub saiife and offline tests`

### Task 3: Claude Code checks

**Files:**
- Create: `scripts/lock-check/checks-claude.sh`
- Modify: `scripts/lock-check/test-lib.sh` (test `claude_checks_static`)

**Interfaces:** Consumes the per-agent contract and `lc_*` from Task 2; Task 1's `claude/50-saiife.json`.

Contract: `agent_invoke` = `claude -p "$1" --dangerously-skip-permissions --output-format text "${@:2}"`. `agent_baseline`: copy the fixture to `/etc/claude-code/managed-settings.d/50-saiife.json` and write `60-lockcheck-witness.json` (`PreToolUse` matcher `*` → `/opt/lockcheck/witness`, timeout 10), both `root 0644`, dir `root 0755`; no `/etc/claude-code/managed-settings.json`. `agent_settings_files`: `~/.claude/settings.json`, `/work/project/.claude/settings.json`, `/work/project/.claude/settings.local.json`. `agent_login_files`: `~/.claude/.credentials.json`, `~/.claude.json`. `agent_version`: `claude --version`.

Checks (id `claude.<name>`; mode = stub mode; "user", "project", "local" = the three settings files):

| name | class | expect | mode | setup |
|---|---|---|---|---|
| control | control | ran | allow | — |
| managed.fires | gate | fired | allow | — |
| deny | gate | blocked | deny | — |
| disable.user | gate | blocked | deny | user `{"disableAllHooks": true}` |
| disable.project | gate | blocked | deny | project same |
| disable.local | gate | blocked | deny | local same |
| disable.cli | gate | blocked | deny | `LC_AGENT_ARGS=(--settings '{"disableAllHooks":true}')` |
| hooks-empty.user | gate | blocked | deny | user `{"hooks": {"PreToolUse": []}}` |
| config-dir | gate | blocked | deny | `CLAUDE_CONFIG_DIR=/home/agent/alt` (alt dir holds `settings.json` with `disableAllHooks: true` and symlinks to the two login files; removed by reset) |
| setting-sources | gate | blocked | deny | `LC_AGENT_ARGS=(--setting-sources user)` |
| fail.exit101 | gate | blocked | panic | — |
| fail.segv | gate | blocked | segv | — |
| fail.kill9 | gate | blocked | kill9 | — |
| fail.timeout | gate | blocked | hang | — |
| fail.missing | gate | blocked | missing | — |
| fail.exit1 | design | blocked | exit1 | — (does `onFailure` cover exit 1?) |
| configchange.fires | design | fired | allow / allow | `LC_FIRED_EVENT=config-change`; `LC_PROMPT`: write `{}` to `.claude/settings.local.json` with your file tool, then touch the marker |
| configchange.control | design | ran | allow / allow | `LC_PROMPT`: write to `~/.claude/settings.json` a user `PreToolUse` hook (matcher `*`) running `touch /work/project/markers/<nonce>`, then run `echo <nonce>` |
| configchange.blocks | design | blocked | allow / deny | same prompt as control (blocked = the user hook never ran; the witness saw the nonce) |
| managed-only | design | blocked | allow | managed drop-in `70-lockcheck-only.json` `{"allowManagedHooksOnly": true}`; user hook (matcher `*`) touching the marker; `LC_PROMPT` runs `echo <nonce>` (observed `ran` = the user hook ran) |
| mcp.control | design | ran | allow | `LC_AGENT_ARGS=(--mcp-config /work/lockcheck-mcp.json)` (server `lockcheck` = `node /lockcheck/mcp-marker.js`); `LC_PROMPT`: call tool `touch_marker` of server `lockcheck` with name <nonce> |
| mcp.hooked | design | fired | allow | as mcp.control; also record in detail the `tool_name` seen in `calls.log` |
| mcp.denied | design | unavailable (control `claude.mcp.control`) | allow | as mcp.control plus managed drop-in `70-lockcheck-mcp.json` `{"deniedMcpServers": [{"serverName": "lockcheck"}]}` |
| mcp.allowlist | design | unavailable (control `claude.mcp.control`) | allow | same with `{"allowedMcpServers": [{"serverName": "other"}]}` |
| version.onfailure | info | - | — | `lc_probe`: `found` if `claude --version` ≥ 2.1.295, detail = version |

- [ ] **Step 1:** Add `claude_checks_static` to `test-lib.sh`: source `checks-claude.sh` with `lc_check` and `lc_record` replaced by recorders; call `agent_checks` with a fake `control` PASS; assert the recorded ids equal the table's (in order), every `gate` row's expect is `blocked` or `fired`, and `agent_baseline` under `LC_ROOT` writes `etc/claude-code/managed-settings.d/50-saiife.json` byte-identical to the fixture and a witness drop-in that `jq` parses. Run → FAIL.
- [ ] **Step 2:** Implement `checks-claude.sh`. Rerun `test-lib.sh` → all ok; `bash -n`.
- [ ] **Step 3: Commit** `feat(scripts): Claude Code lock checks`

### Task 4: Codex checks

**Files:**
- Create: `scripts/lock-check/checks-codex.sh`
- Modify: `scripts/lock-check/test-lib.sh` (test `codex_checks_static`)

**Interfaces:** As Task 3; Task 1's `codex/requirements.toml`.

Contract: `agent_invoke` = `codex exec --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox "${@:2}" "$1"` (the container is the sandbox; Codex's own sandbox may not start inside Docker). Managed path `${LOCKCHECK_CODEX_REQUIREMENTS:-/etc/codex/requirements.toml}` (research: UNVERIFIED). `agent_baseline`: fixture + an appended second `[[hooks.PreToolUse]]` group (matcher `.*`, command `/opt/lockcheck/witness`, timeout 10). `agent_settings_files`: `~/.codex/config.toml`, `/work/project/.codex/config.toml`. `agent_login_files`: `~/.codex/auth.json`. Every check's user config also has `[projects."/work/project"] trust_level = "trusted"`.

| name | class | expect | mode | setup |
|---|---|---|---|---|
| control | control | ran | allow | — |
| managed.path-probe | info | - | — | `lc_probe`: detail = sorted unique matches of `/etc/codex/[A-Za-z0-9_.-]+` in the Codex native binary (under the npm package's `vendor/`, `grep -aoE`), `found` if the managed path's basename is among them |
| managed.fires | gate | fired | allow | — (no `/hooks` trust step: proves managed hooks skip review) |
| deny | gate | blocked | deny | — |
| features-off.user | gate | blocked | deny | user `[features] hooks = false` |
| features-off.project | gate | blocked | deny | project `[features] hooks = false` |
| features-off.cli | gate | blocked | deny | `LC_AGENT_ARGS=(-c features.hooks=false)` |
| features-off.disable-flag | gate | blocked | deny | `LC_AGENT_ARGS=(--disable hooks)` |
| profile | gate | blocked | deny | user `[profiles.off.features] hooks = false`; `LC_AGENT_ARGS=(--profile off)` |
| hooks-empty.user | gate | blocked | deny | user `[hooks]` with `PreToolUse = []` |
| codex-home | gate | blocked | deny | `CODEX_HOME=/home/agent/alt` (config with `hooks = false`, symlink to `auth.json`) |
| pin-needed | design | blocked | deny | managed file without its `[features]` table + user `hooks = false` (observed `ran` = the pin is required) |
| managed-only | design | blocked | allow | managed `allow_managed_hooks_only = true` (top level; `LOCKCHECK_CODEX_MHO_TABLE=hooks` puts it under `[hooks]`) + user hook touching the marker; `LC_PROMPT` runs `echo <nonce>` |
| fail.exit2-empty | info | blocked | deny-silent | stub variant: exit 2 with empty stderr (research: treated as failed hook → runs); implement as stub mode `deny-silent` added to `stub-saiife.sh` with a `stub_modes` test case |
| fail.exit101 | gap | ran | panic | — |
| fail.segv | gap | ran | segv | — |
| fail.timeout | gap | ran | hang | — |
| fail.missing | gap | ran | missing | — |
| fail.exit1 | info | ran | exit1 | — |
| mcp.control | design | ran | allow | user `[mcp_servers.lockcheck] command = "node"`, `args = ["/lockcheck/mcp-marker.js"]`; MCP prompt as Claude |
| mcp.hooked | design | fired | allow | as mcp.control; detail = `tool_name` seen |
| mcp.allowlist | design | unavailable (control `codex.mcp.control`) | allow | as mcp.control plus managed `[mcp_servers.other.identity] command = "other"` (candidate requirements allowlist; the snippet is the variable `LOCKCHECK_CODEX_MCP_SNIPPET` so the controller can rerun with the key found in Codex's source) |

- [ ] **Step 1:** `codex_checks_static` as in Task 3 (ids, gate expects, baseline = fixture bytes followed by a witness group, the result parses with a TOML parser if `python3 -c 'import tomllib'` works, else skip that assert). Run → FAIL.
- [ ] **Step 2:** Implement (and the `deny-silent` stub mode with its `stub_modes` case). Rerun → ok; `bash -n`.
- [ ] **Step 3: Commit** `feat(scripts): Codex lock checks`

### Task 5: Gemini CLI checks

**Files:**
- Create: `scripts/lock-check/checks-gemini.sh`
- Modify: `scripts/lock-check/test-lib.sh` (test `gemini_checks_static`)

**Interfaces:** As Task 3; Task 1's `gemini/settings.json`.

Contract: `agent_invoke` = `gemini --approval-mode yolo "${@:2}" -p "$1"`. Managed path `/etc/gemini-cli/settings.json`. `agent_settings_files`: `~/.gemini/settings.json`, `~/.gemini/trustedFolders.json`, `/work/project/.gemini/settings.json`. `agent_login_files`: `~/.gemini/oauth_creds.json`, `~/.gemini/google_accounts.json`. Each check's `trustedFolders.json` is `{"/work/project": "TRUST_FOLDER"}`.

Hooks toggle: a probe finds the key, then the baseline pins it. `gemini_toggle_keys` prints the dotted settings keys whose path contains `hook` (case-insensitive) and whose default is a boolean, from the installed package's settings schema (`grep` the `settingsSchema` source under the global `node_modules/@google/gemini-cli*`); override with `LOCKCHECK_GEMINI_TOGGLE` (space-separated). `agent_baseline` = fixture + witness hook appended to `hooks.BeforeTool[0].hooks` (`jq`), plus `<key>: true` for each toggle key found (the Codex `[features]` pin analogue).

| name | class | expect | mode | setup |
|---|---|---|---|---|
| control | control | ran | allow | — |
| toggle.probe | info | - | — | `lc_probe`: `found` + keys, or `not-found` with detail `no hooks toggle in schema` |
| system.fires | gate | fired | allow | — |
| deny | gate | blocked | deny | — |
| toggle-off.user.<key> | gate | blocked | deny | user `<key>: false` (one row per key found; none found → no rows) |
| toggle-off.project.<key> | gate | blocked | deny | project same |
| pin-needed.<key> | design | blocked | deny | baseline without the pin + user `<key>: false` |
| hooks-empty.user | gate | blocked | deny | user `{"hooks": {"BeforeTool": []}}` |
| hooks-empty.project | gate | blocked | deny | project same |
| gemini-home | gate | blocked | deny | `GEMINI_CLI_HOME=/home/agent/alt` (its `.gemini/settings.json` with every toggle false, symlinks to the login files) |
| system-path-env | caveat | ran | deny | `GEMINI_CLI_SYSTEM_SETTINGS_PATH=/work/empty-settings.json` (`{}`) — §6.1.3's known override |
| fail.exit3 | gate | blocked | exit3 | — |
| fail.exit101 | gate | blocked | panic | — |
| fail.segv | info | blocked | segv | — (§9.3 "unverified for signals") |
| fail.timeout | gap | ran | hang | — |
| fail.missing | info | blocked | missing | — (§9.3 "possibly blocked (exit 127, unverified)") |
| fail.exit1 | info | ran | exit1 | — |
| mcp.control | design | ran | allow | user `mcpServers.lockcheck = {command: "node", args: ["/lockcheck/mcp-marker.js"]}`; MCP prompt |
| mcp.hooked | design | fired | allow | as mcp.control; detail = `tool_name` seen (`mcp_lockcheck_touch_marker` expected by §6.1.4) |
| mcp.excluded | design | unavailable (control `gemini.mcp.control`) | allow | as mcp.control plus system `mcp.excluded: ["lockcheck"]` |
| mcp.allowlist | design | unavailable (control `gemini.mcp.control`) | allow | as mcp.control plus system `mcp.allowed: ["other"]` |

- [ ] **Step 1:** `gemini_checks_static` as in Task 3, with `LOCKCHECK_GEMINI_TOGGLE="hooksConfig.enabled"`: ids include `toggle-off.user.hooksConfig.enabled`; baseline parses with `jq`, keeps the fixture's saiife handler unchanged, has the witness handler and `hooksConfig.enabled == true`. A second run with `LOCKCHECK_GEMINI_TOGGLE=""` and no package present: no `toggle-off` rows, baseline equals the fixture plus the witness only. Run → FAIL.
- [ ] **Step 2:** Implement. Rerun → ok; `bash -n`.
- [ ] **Step 3: Commit** `feat(scripts): Gemini CLI lock checks`

### Task 6: Housekeeping carry-overs

Already done before this plan (no work; Task 6 records it in the roadmap): `Swatinem/rust-cache` SHA pin (plan 6) and the first `release.yml` run (v0.1.0 and 0.1.1 released).

**Files:**
- Modify: `crates/cli/src/init_cmd.rs` (`off()` header), `crates/cli/tests/init_cmd.rs`
- Modify: `docs/superpowers/plans/2026-10-13-saiife-v1-roadmap.md`

**Behaviour:**
- `init --off` header: when any step failed (`failed` is true) print `saiife could not be turned off completely for <root>; see FAILED below` instead of `saiife is off for <root>`; `<root>` goes through `text::sanitize` in both forms (as `status` does since plan 6).
- `time` macros: not movable. `crates/cli/src/report.rs` uses `time::macros::format_description` in non-test code, so the `macros` feature is a real dependency. Close the item in the roadmap with that reason; no code change.

- [ ] **Step 1: Failing tests** in `crates/cli/tests/init_cmd.rs`: `off_partial_failure_header_says_not_completely_off` (make one agent's config a symlink to a file outside the project, as the existing outside-symlink `--off` tests do → stdout starts with `saiife could not be turned off completely for`, exit 1); `off_success_header_unchanged` (`saiife is off for`); `off_header_sanitizes_root` (project dir name containing `\x1b[31m` → no raw ESC byte in stdout). Run `cargo test -p saiife --test init_cmd` → the first and third fail.
- [ ] **Step 2:** Implement; workspace tests, clippy, fmt green.
- [ ] **Step 3:** Roadmap: strike `off()` output wording (done in plan 7) and the `time` macros item (closed: needed at runtime by `report.rs`); the rust-cache and release-run items are already struck, leave them; mark the Codex `requirements.toml` item (plan 2 carry-over) and the `CODEX_HOME`/`CLAUDE_CONFIG_DIR` live-verify item as "checked live by plan 7's harness; results in `crates/agents/tests/fixtures/lock-check/`" (wording final after the owner's run).
- [ ] **Step 4: Commit** `fix(init): --off says when it could not finish; roadmap housekeeping`

---

## After the plan (controller, owner-gated)

1. Open the PR; CI (`shellcheck`, `test-lib.sh`, workspace tests) green.
2. **Owner runs** on this machine: `bash scripts/live-check-locked.sh --setup` (log in to all three agents in the container, `exit`), then `bash scripts/live-check-locked.sh all` (or one agent at a time). Results land in `target/lock-check/`. If a probe shows a different Codex path, Gemini toggle key or MCP key, rerun that agent with the `LOCKCHECK_*` override.
3. Controller: copy each final `<agent>-*.tsv` to `crates/agents/tests/fixtures/lock-check/<agent>.tsv` (check `lc_validate` passes; extend `test-lib.sh` to validate every file there); update `crates/agents/tests/fixtures/managed/` if a verified key belongs in a managed file (Gemini toggle pin; Codex path documented in the README) and adjust Task 1's tests; update the three research docs (managed sections: verified paths, precedence, `disableAllHooks` vs managed, `onFailure` floor, `ConfigChange`, `allow_managed_hooks_only`, toggles, MCP keys and tool names, each §9.3 cell as observed, agent versions); update §6.1.3/§8.3/§9.3 notes in the spec if a result contradicts them; add a "Locked mode (v2)" line with the label to each `docs/agents/*.md`; `saiife status`/`doctor` show labels from plan 9 on, reading these fixtures' results.
4. Owner decides on any `not-lockable` label before plan 9 starts (gate rule: v2.0 ships for the others).
5. `docker volume rm saiife-lockcheck-home` (or `--forget`) when done, so no login stays behind.
