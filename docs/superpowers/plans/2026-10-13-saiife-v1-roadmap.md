# saiife v1 — plan roadmap

The v1 spec (`docs/superpowers/specs/2026-10-13-saiife-cli-v1-design.md`)
is split into five plans. Each one ends with working, tested software and is
written in full only when the previous one is done, so it can build on the
real code instead of guesses.

| # | Plan | Spec sections | Delivers | Status |
|---|---|---|---|---|
| 1 | Foundation + audit log | §3, §4, §6.1–6.3, §8 (CI offline), §11 | `saiife` binary in the new repo; every decision audited and masked; `saiife audit` table; CI incl. offline run | written: `2026-10-13-plan-1-foundation-audit.md` |
| 2 | Agents + project config + tamper detection | §5, §5.1, §5.2, §7.5, §9.1 (reserved field) | `.saiife/config.toml`; `init`, `init --off`, `status` with integrity checks, `packs`; hooks (shell, read and write tools) for Claude Code, Codex, Gemini, verified against live installs and recorded fixtures | written: `2026-10-13-plan-2-agents-config-tamper.md` |
| 3 | Secret and self protection | §7.1–7.4 | `core.secrets` (incl. cloud secret reads), `core.self`; `evaluate_path` for read and write tools | written: `2026-10-13-plan-3-secret-self-protection.md` |
| 4 | HTML report | §6.4 | `saiife audit --report`, self-contained, DPO-readable | written: `2026-10-18-plan-4-html-report.md` |
| 5 | Release, docs, demo | §8, §10 (pack docs), §12 (incl. threat-coverage docs per §1.1) | release CI for 4 targets, `install.sh`, one docs page per pack, Codex + Ollama recipe, demo script | to write after plan 4 |

Order rationale: plan 2 needs plan 1's `check --agent`; plan 3 needs plan 2's
read-tool hook wiring; plan 4 needs the final record shape; plan 5 packages
everything.

v2 (admin lock, connector gateway, tamper-evident audit) and v3 (isolated
runner) are designed in spec §9 and get their own specs after v1 ships.

## Carry-over from plan 1 (for the plans that own them)

- ~~**Plan 2:** `saiife check` answers Claude Code with `permissionDecision: "allow"`~~ — done in plan 2: allow is silent for every agent.
- ~~**Plan 2 (`status`):** `read_all` returns an empty result with no signal when the audit dir itself is unreadable~~ — done in plan 2: `ReadResult::dir_error`; `status` and `audit` report it.
- ~~**Plan 4 (report):** escape LRM/RLM/ALM (U+200E/U+200F/U+061C) too; show a project column; mask `mysql -pPASS`; stop the URL rule over-masking across `"`/`'`/`,` (e.g. `https://h","email":"a@b.c`).~~ — done in plan 4: `saiife audit --report` writes the HTML report with a project column; the escaping and masking fixes landed earlier in plan 4.
- **Any plan touching `check`:** payloads over 1 MiB are still logged with empty input; engine abort/stack overflow is not caught (only panics).
- **Housekeeping:** ~~audit dir 0700, checked arithmetic for `--since`~~, `time` macros as cli dev-dependency, ~~clean up `/tmp/saiife-test-audit-*` in tests~~ — done in plan 5a (the `time` macros item stays open).

## Carry-over from plan 2 (for the plans that own them)

- ~~**Plan 3 (path rules):** Claude `Glob`/`LS` are classified as Other, and an `apply_patch` whose patch yields no paths is recorded with empty input~~ — done in plan 3: `Glob`/`LS` are read tools; a file call with no path is `error_allowed` "no path to judge".
- ~~**Plan 3 (Codex layout):** an inline `hooks = [{…}]` / `hooks = { PreToolUse = […] }` layout is refused as a whole~~ — done in plan 3: saiife appends its group to the user's inline array and removes only it.
- **Plan 5 (verify live, moved from plan 3):** Codex and Gemini CLI hook entries are built from the research docs but not yet run against a live install (no Codex/Gemini install on the dev machine; the research marks these UNVERIFIED): Codex `/hooks` trust flow, `apply_patch` patch text in `tool_input.command`, project `config.toml` hooks loading; Gemini `name`/ms timeout and folder trust. Plan 5's demo and per-agent docs pages need a live run anyway.
- **Plan 5 (Gemini, verify live + docs, moved from plan 3):** whether a missing `saiife` on PATH (exit 127) blocks every Gemini tool; document it on the Gemini docs page.
- **Plan 5 (Gemini status, moved from plan 3):** Gemini CLI's setting to enable/disable hooks is not named in the research, so `status` stays blind to it until a live install shows the key.
- **Plan 5 (Codex status, moved from plan 3):** managed `requirements.toml` `allow_managed_hooks_only` is not checked; the research marks its path UNVERIFIED (likely `/etc/codex/`).
- ~~**Plan 5 (status performance):** `last_calls` loads the whole audit log to find the last hook call per agent.~~ — done in plan 5a: `store::read_recent` reads the newest month files only.
- ~~**Status/init UX:** when `.saiife/config.toml` was removed, `status` run from a subdirectory looks for the project at the subdirectory and says "not set up" instead of naming the removed config; a partial `init --off` (one agent failed) leaves a stale integrity record; `off()` output wording; an existing integrity record directory is not tightened to 0700; a dangling symlinked agent config gives an unclear I/O error.~~ — done in plan 5a: clearer messages and records after partial or broken setups.
- **Status/init UX:** `off()` output wording.
- ~~**Status/init UX:** a failed agent's error entry in the integrity record cannot be cleared on its own (only by a successful `saiife init` for that agent, or `init --off`).~~ — done in plan 5a: clearer messages and records after partial or broken setups.
- ~~**Status/init UX:** a hook installed before plan 2 through a symlinked agent config that points outside the project can no longer be removed by `init --off` (now refused); add a cleanup hint naming the outside file.~~ — done in plan 5a: clearer messages and records after partial or broken setups.
- **CI:** the M4 unhashable-binary test (`unhashable_binary_at_init_is_a_failed_check`) skips in the offline job (root in a user namespace can read an execute-only file); it is covered by the ubuntu and macOS jobs.

## Carry-over from plan 3 (for the plans that own them)

- **Accepted false positives (`core.self`, by design):** `eval` and `source`/`.` have an effect the guard cannot see, so they count as an environment change and a nested agent after them in the same command line is denied: `eval "$(ssh-agent -s)"; claude …`, `eval "$(direnv hook bash)" && codex …`, `source venv/bin/activate; claude …`. The agent can run the nested agent as a separate command.
- **Known gaps (`core.self`):** `unset HOME` / `export -n HOME` / `declare +x PATH` before a nested agent are not treated as environment changes; a dynamic argv[0] (`$(echo saiife) init --off`) is not judged; a plain `$PATH` hidden in a here-document body or comment can offset one obfuscated `$PATH` spelling elsewhere on the line (adversarial only); `codex --profile` can select a user profile with other hook settings.
- **Plan 5 (docs, `core.secrets` page):** stated limits: a script the agent writes and runs, a recursive read of a directory that holds a secret (`grep -r KEY .`, `cp -r ~/.ssh x`), `git show HEAD:.env`, `find … -exec cat {} +` and `xargs` are not seen; Gemini `read_many_files` with a broad glob (`**/*`) relies on Gemini's own git-ignore handling; `kubectl describe secret` is allowed (values are redacted); `aws configure get` is denied only for secret/token/password/key names; a recursive `Grep`/`rg` of a root without a glob is not judged per file (rg skips hidden and git-ignored files by default; the plan 5 live check confirms).
- **Plan 5 (docs, `core.self` page):** `saiife init --off` works in the user's own terminal (not hooked); a shell function named `saiife` is not detected; `git stash` (whole worktree) is not judged; `unset SAIIFE_AUDIT_DIR` only affects that subshell; `cat $(echo -e '.\x65nv')` and `cat $(ls)` (unresolved substitution operands of file readers) are skipped silently, an escape-encoded name being a determined bypass (§7.3); `export PATH=$PATH:./{a,b}` is over-denied.
- **Plan 5 (check):** with path rules, the plan 1 carry-over "payloads over 1 MiB are logged with empty input" is closed for path fields (they are stream-parsed with no cap); recheck on live installs. `CODEX_HOME` and `CLAUDE_CONFIG_DIR` come from product docs, not from our research docs: verify live and note them in the research doc.
- ~~**Plan 5 (status):** `explain`/`packs <id>` say "inactive on this machine: $VAR unbound" for skipped path rules; `status` does not yet show a note for them.~~ — done in plan 5a: `status` prints `inactive here: $VAR is not set: <packs>` under the packs line.
- **Plan 5 (housekeeping, minors from reviews):** an unresolvable-path reason also covers symlink loops; about 2000 nested real directories may exceed the 50 ms path budget (bounded, visible in the audit); one non-UTF-8 value in a multi-valued `SAIIFE_BIN` drops the whole rule; a 4096-byte absolute path skips symlink resolution under a very deep cwd; path resolution runs before the first budget check; ~~a raw path in an Unjudgeable audit reason may bypass masking~~ (done in plan 5a: `reason` is masked in `Record::at`); the `status` upgrade test lacks a second-init no-op, `--off` after an upgrade and Codex/Gemini passing next to an old Claude entry; the one `check_audit` `concurrent_checks_write_whole_lines` failure ("stream did not contain valid UTF-8") fits a disk-quota hit mid-line, not interleaving: ~~harden the test to read bytes through `read_all`~~ (done in plan 5a).
- **v2 (admin lock):** Claude Code's `ConfigChange` hook could block settings edits made outside tool calls; not used in v1.
- **Plan 5 (deferred from the plan-3 final review, with reasons):** ~~split `evaluate_inner`/`lex_in` (a `ShellState` struct and one `recurse` helper)~~ — done in plan 5a (decision-identical over the full corpus); Codex `init --off` keeps a user's own empty `PreToolUse = []` (an empty array has no effect, no setting is lost); CRLF in `.codex/config.toml` is kept (pre-existing on main, needs a `toml_edit` rewrite); Codex inline-layout tests for comments in the array, a shared matcher, array-of-tables plus inline and `status` after an inline install (verified by hand); `xargs` long options by unique prefix (`--arg=.env`; an abbreviated option is a deliberate spelling, §7.3); the raw `$PATH` scanner reading comments and here-document bodies (adversarial decoy only, see Known gaps); ~~audit `reason` not masked~~ — done in plan 5a (`reason` is masked in `Record::new`); write targets from an unresolved substitution (`cp /bin/true $(command -v saiife)`) are skipped (needs audit-noise data first); glob expansion for file tools runs outside the 50 ms budget (bounded per pattern); ~~per-call fixed cost about 33 ms against 18 ms on main (profile, lazy path rules)~~ — done in plan 5a (about 16 ms: only active packs compiled, path rules bound once); `source .env && npm start` / `set -a; . ./.env` denied (document, decide on live use); `git restore --staged .claude/settings.json` denied (rare); `rm -rf target` denied when the `saiife` on PATH is a build inside it (document for dogfooding); ~~agents' own credential files (`~/.claude/.credentials.json`, `~/.codex/auth.json`, `~/.gemini/oauth_creds.json`) are readable (one path rule each).~~ — done in plan 5a
- **Plan 5 (docs, from the final wave):** a line that names `IFS` records unquoted substitution values as `error_allowed` unless something denies (a custom `IFS` may split where neither the default split nor the unsplit value does); a here-document inside `$(…)` ends at a line that starts with its delimiter and holds a `)`, as in bash 5.3 (older bash and zsh may differ).
- Fixed in the plan-3 final wave (listed so the record is complete): the macOS CI job (the `PROJECT` binding test now accepts both the spelled and the resolved temp dir; the `check` fixtures that spell `/home/u` run in a real temp home, since `/home` is an autofs mount on macOS and resolving through it ran past the budget; CI runs `cargo test --no-fail-fast`); corpus and exact-trace tests use a 5 s budget (`DEFAULT_BUDGET` unchanged, the budget path keeps its own tests); `aws configure get` with any flag before the key; `kubectl get --raw` of any path naming `secrets` (query strings) or holding a `%` escape; `env --version`/`--help` no longer denied; a file tool's malformed `tool_input` is `error_allowed` "malformed tool_input" (and the buffering comment is corrected); every nested-evaluation depth cap records "… nested too deeply to judge"; unquoted substitution values are judged both split and unsplit, each as its own argv, instead of being skipped when `IFS` appears on the line; `case` patterns inside `$(…)` no longer close it; an `EOF)` delimiter line inside `$(…)` ends the here-document; here-documents opened in arithmetic are read after the line; a cut-off `((` look-ahead never opens a here-document.

## Carry-over from plan 4 (for the plans that own them)

- **Plan 5 (masking, `mysql -p`):** `mysql -psecret;ls` masks `secret;ls` (over-masks, safe side). A URL userinfo password with a quote directly followed by `,` `}` `]` `)` `;` `&` `|` or a space is not masked: that is the trade-off that stops the rule from masking across JSON (`https://h","email":"a@b.c`).
- **Plan 5 (report):**
  - ~~A relative project string (only possible in a hand-edited log) resolves against the cwd.~~ — done in plan 5a.
  - ~~The "could not be read" note says "in this folder" even when the unreadable config belongs to a parent folder.~~ — done in plan 5a.
  - The report file is 0600, like the audit log: run `chmod` to share it with another local account.
  - The report shows packs as configured today, not as they were during the period. v2's tamper-evident log could record the active packs per decision.
- **Plan 5 (report tests and polish):**
  - ~~The summary count asserts are weak: assert `<dd>N</dd>`. The order test should match `<h2>`.~~ — done in plan 5a.
  - ~~The print CSS for a closed `<details>` has no effect. `<h4>` is unstyled. An empty projects or agents list gives a blank `<dd>`. "Show all 1 decisions" needs a plural.~~ — done in plan 5a.
  - Untested: ~~the "log files could not be read" string~~ (done in plan 5a); cleanup after a write or rename failure; equal-timestamp order.
  - The no-config test assumes there is no `.saiife/config.toml` above the temp dir.
  - The 10 s wall-clock limit on the 20 000-record test may be tight on a slow macOS runner.
- **Plan 5 (housekeeping):** ~~in `audit_cmd::run`, the `report` parameter shadows the `report` module, and the names `since_arg`/`since` are confusing~~ (done in plan 5a). Unix-only test code has no `cfg(unix)`; there is no Windows CI.
- **Plan 5 (manual check):** look at the report at phone width and in print preview in a real browser. During plan 4 it was checked as HTML only.

## Carry-over from plan 5a (for the plans that own them)

- **Done in plan 5a (PR #2 follow-up):** an allow rule now exempts only its own pack. A deny from any other pack still wins.
- ~~**Plan 5b (docs, known over-denies):** zsh 5.9 and dash over-deny three here-document-in-`$(…)` shapes. This is the safe direction. They are listed in `KNOWN_NON_BASH_OVER_DENIES` (`shell_differential` test); document them.~~ — done in plan 5b
- **Plan 5b (guard engine):** — done in plan 5b
  - ~~Stale "judged above/below" comments in `SegmentView::new` and `command_position_phase` (`engine.rs`): name the phase methods. `environment_phase` has an unused `&self`.~~ — done in plan 5b
  - ~~`refactor_equivalence`: the `CORPUS.len() >= 60` assert is constant, and denies are matched by pack only, not by pattern.~~ — done in plan 5b
  - ~~Cross-pack allow scoping: no test in `cross_pack.rs`, and no test that two allowing packs return the first trace. An allow no longer short-circuits (small perf cost). An early allow followed by a later-pack timeout is now a timeout fail-open (still recorded, not a bypass).~~ — done in plan 5b
  - ~~"Bind path rules lazily" oversells: the rules are bound on every call, and the gain is compiling each glob once. Fix the `with_paths` doc comment.~~ — done in plan 5b
- ~~**Plan 5b (guard lexer):** `_ =>` arms in the operator and quote handling rely on `step()` routing (use explicit arms and `unreachable!()`); the merged `,`/`}` brace arm; some helpers return `()`.~~ — done in plan 5b
- **Plan 5b (docs, `core.secrets` and paths):**
  - ~~A relative `CLAUDE_CONFIG_DIR` used by the agent is not resolved against the hook's cwd; inline `CLAUDE_CONFIG_DIR=/x cat /x/.credentials.json` is not covered; Gemini `GEMINI_CLI_HOME` is not covered.~~ — done in plan 5b
  - The `core.secrets` comment wording and the HOME-unknown case.
- ~~**Plan 5b (shell differential tests):** the shell list and `cases()` are rebuilt per shell; the tolerance list is keyed to the zsh version; shell startup files (`~/.zshenv`, `BASH_ENV`) run with the real HOME; one collapsible else-if.~~ — done in plan 5b
- **Plan 5b (status and audit):** — done in plan 5b
  - ~~"no call in the last 12 months" also shows on a brand-new install and for an agent hooked yesterday: "no call yet" fits when the scan was not cut short.~~ — done in plan 5b
  - ~~`store::read_recent`: an empty month file leaves `more = true`, so with no hooked agent `status` reads up to 12 files for nothing; short-circuit first.~~ — done in plan 5b
  - ~~The CLI wiring of the inactive note in `packs <id>`/`explain` is only unit-tested (render and `inactive_summary`); hoist `ts` in the `read_recent` test; `read_recent_stops_early` had no RED run.~~ — done in plan 5b
  - ~~`status_root`: a parent's `.saiife/config.toml` hides a nearer project whose config was removed (pre-existing in shape).~~ — done in plan 5b
- **Plan 5b (init and housekeeping):** — done in plan 5b
  - ~~A symlink chain with a dangling end reports the first link's target.~~ — done in plan 5b
  - ~~An existing looser audit dir is not tightened (new dirs are 0700; files are 0600 anyway).~~ — done in plan 5b
  - ~~The `--since` error text is duplicated; no test that an ordinary path in a reason stays unmasked; the 16 KB check measures the re-serialized record.~~ — done in plan 5b
  - ~~The pack loader words a valid-header, broken-rules enabled pack as "failed to load"; `load_active` copies `select_active`'s filter (pinned by a test); warnings show only on shell and file calls (R17).~~ — done in plan 5b
- **Plan 5c (release, bench, CI):** `scripts/bench-check.sh` hard-codes `$repo/target/release/saiife` and ignores `CARGO_TARGET_DIR`.
- ~~**Plan 5b (status wording):** an agent whose earlier `init` failed and whose config sits behind an outside symlink can get the "hook is still in place" text on `--off`, which may be untrue (`status_cmd.rs`).~~ — done in plan 5b

## Carry-over from plan 5b (for the plans that own them)

- The guard does not block `cd / && rm -rf *`: `cd` is not tracked. It is listed as not covered in `docs/packs/core.filesystem.md`.
- The hook's project lookup is config-only, while `status` and `init` also accept an integrity record (minor; `core.self` denies writes to `**/.saiife/**`).
- Audit directory tightening chmods any loose real directory that the user owns and set through `SAIIFE_AUDIT_DIR`.
- `dollar()` keeps its `_ =>` arm as a real fallback.
- The docs link test does not check `#anchors` or `~~~` fences.
- `shellcheck` is not run on the scripts (not installed here). Add it to CI in plan 5c.
- `status` could warn about nested `.saiife/config.toml` files that have no integrity record. A stray nested config with `packs = []` turns opt-in packs off for hooks run from that directory. Only a script can create one (`core.self` blocks shell and write tools).

## User checks (plan 5c gate)

- Run `scripts/live-check-agents.sh` (Codex, Gemini).
- Verify the Codex + Ollama recipe and the `[model_providers.ollama]` key.
- Look at the HTML report at phone width and in print preview.
- `scripts/bench-check.sh` must honour `CARGO_TARGET_DIR` (plan 5c).
