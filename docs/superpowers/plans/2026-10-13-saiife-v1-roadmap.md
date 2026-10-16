# saiife v1 — plan roadmap

The v1 spec (`docs/superpowers/specs/2026-10-13-saiife-cli-v1-design.md`)
is split into five plans. Each one ends with working, tested software and is
written in full only when the previous one is done, so it can build on the
real code instead of guesses.

| # | Plan | Spec sections | Delivers | Status |
|---|---|---|---|---|
| 1 | Foundation + audit log | §3, §4, §6.1–6.3, §8 (CI offline), §11 | `saiife` binary in the new repo; every decision audited and masked; `saiife audit` table; CI incl. offline run | written: `2026-10-13-plan-1-foundation-audit.md` |
| 2 | Agents + project config + tamper detection | §5, §5.1, §5.2, §7.5, §9.1 (reserved field) | `.saiife/config.toml`; `init`, `init --off`, `status` with integrity checks, `packs`; hooks (shell, read and write tools) for Claude Code, Codex, Gemini, verified against live installs and recorded fixtures | written: `2026-10-13-plan-2-agents-config-tamper.md` |
| 3 | Secret and self protection | §7.1–7.4 | `core.secrets` (incl. cloud secret reads), `core.self`; `evaluate_path` for read and write tools | to write after plan 2 |
| 4 | HTML report | §6.4 | `saiife audit --report`, self-contained, DPO-readable | to write after plan 3 |
| 5 | Release, docs, demo | §8, §10 (pack docs), §12 (incl. threat-coverage docs per §1.1) | release CI for 4 targets, `install.sh`, one docs page per pack, Codex + Ollama recipe, demo script | to write after plan 4 |

Order rationale: plan 2 needs plan 1's `check --agent`; plan 3 needs plan 2's
read-tool hook wiring; plan 4 needs the final record shape; plan 5 packages
everything.

v2 (admin lock, connector gateway, tamper-evident audit) and v3 (isolated
runner) are designed in spec §9 and get their own specs after v1 ships.

## Carry-over from plan 1 (for the plans that own them)

- ~~**Plan 2:** `saiife check` answers Claude Code with `permissionDecision: "allow"`~~ — done in plan 2: allow is silent for every agent.
- ~~**Plan 2 (`status`):** `read_all` returns an empty result with no signal when the audit dir itself is unreadable~~ — done in plan 2: `ReadResult::dir_error`; `status` and `audit` report it.
- **Plan 4 (report):** escape LRM/RLM/ALM (U+200E/U+200F/U+061C) too; show a project column; mask `mysql -pPASS`; stop the URL rule over-masking across `"`/`'`/`,` (e.g. `https://h","email":"a@b.c`).
- **Any plan touching `check`:** payloads over 1 MiB are still logged with empty input; engine abort/stack overflow is not caught (only panics).
- **Housekeeping:** audit dir 0700, checked arithmetic for `--since`, `time` macros as cli dev-dependency, clean up `/tmp/saiife-test-audit-*` in tests.

## Carry-over from plan 2 (for the plans that own them)

- **Plan 3 (path rules):** Claude `Glob`/`LS` are classified as Other, and an `apply_patch` whose patch yields no paths is recorded with empty input; both must be "unjudgeable" (fail open, recorded as such) once path rules exist.
- **Plan 3 (verify live):** Codex and Gemini CLI hook entries are built from the research docs but not yet run against a live install: Codex `/hooks` trust flow, `apply_patch` patch text in `tool_input.command`, project `config.toml` hooks loading; Gemini `name`/ms timeout and folder trust.
- **Plan 3 (Gemini, verify live + docs):** whether a missing `saiife` on PATH (exit 127) blocks every Gemini tool; document it on the Gemini docs page and re-check live.
- **Plan 3 (Gemini status):** Gemini CLI's setting to enable/disable hooks is unverified, so `status` is blind to it (no blocker check for Gemini).
- **Plan 3 (Codex status):** managed `requirements.toml` `allow_managed_hooks_only` is not checked (its path is unverified).
- **Plan 3 (Codex layout):** an inline `hooks = [{…}]` / `hooks = { PreToolUse = […] }` layout is refused as a whole; refuse only when it holds saiife's own entry.
- **Plan 5 (status performance):** `last_calls` loads the whole audit log to find the last hook call per agent.
- **Status/init UX:** when `.saiife/config.toml` was removed, `status` run from a subdirectory looks for the project at the subdirectory and says "not set up" instead of naming the removed config; a partial `init --off` (one agent failed) leaves a stale integrity record; `off()` output wording; an existing integrity record directory is not tightened to 0700; a dangling symlinked agent config gives an unclear I/O error.
- **Status/init UX:** a failed agent's error entry in the integrity record cannot be cleared on its own (only by a successful `saiife init` for that agent, or `init --off`).
- **Status/init UX:** a hook installed before plan 2 through a symlinked agent config that points outside the project can no longer be removed by `init --off` (now refused); add a cleanup hint naming the outside file.
- **CI:** the M4 unhashable-binary test (`unhashable_binary_at_init_is_a_failed_check`) skips in the offline job (root in a user namespace can read an execute-only file); it is covered by the ubuntu and macOS jobs.

## Carry-over from plan 3 (for the plans that own them)

- **Accepted false positives (`core.self`, by design):** `eval` and `source`/`.` have an effect the guard cannot see, so they count as an environment change and a nested agent after them in the same command line is denied: `eval "$(ssh-agent -s)"; claude …`, `eval "$(direnv hook bash)" && codex …`, `source venv/bin/activate; claude …`. The agent can run the nested agent as a separate command.
- **Known gaps (`core.self`):** `unset HOME` / `export -n HOME` / `declare +x PATH` before a nested agent are not treated as environment changes; a dynamic argv[0] (`$(echo saiife) init --off`) is not judged; a plain `$PATH` hidden in a here-document body or comment can offset one obfuscated `$PATH` spelling elsewhere on the line (adversarial only); `codex --profile` can select a user profile with other hook settings.
