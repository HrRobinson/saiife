# saiife v1 — plan roadmap

The v1 spec (`docs/superpowers/specs/2026-10-13-saiife-cli-v1-design.md`)
is split into five plans. Each one ends with working, tested software and is
written in full only when the previous one is done, so it can build on the
real code instead of guesses.

| # | Plan | Spec sections | Delivers | Status |
|---|---|---|---|---|
| 1 | Foundation + audit log | §3, §4, §6.1–6.3, §8 (CI offline), §11 | `saiife` binary in the new repo; every decision audited and masked; `saiife audit` table; CI incl. offline run | written: `2026-10-13-plan-1-foundation-audit.md` |
| 2 | Agents + project config + tamper detection | §5, §5.1, §5.2, §7.5, §9.1 (reserved field) | `.saiife/config.toml`; `init`, `init --off`, `status` with integrity checks, `packs`; hooks (shell, read and write tools) for Claude Code, Codex, Gemini, verified against live installs and recorded fixtures | to write after plan 1 |
| 3 | Secret and self protection | §7.1–7.4 | `core.secrets` (incl. cloud secret reads), `core.self`; `evaluate_path` for read and write tools | to write after plan 2 |
| 4 | HTML report | §6.4 | `saiife audit --report`, self-contained, DPO-readable | to write after plan 3 |
| 5 | Release, docs, demo | §8, §10 (pack docs), §12 (incl. threat-coverage docs per §1.1) | release CI for 4 targets, `install.sh`, one docs page per pack, Codex + Ollama recipe, demo script | to write after plan 4 |

Order rationale: plan 2 needs plan 1's `check --agent`; plan 3 needs plan 2's
read-tool hook wiring; plan 4 needs the final record shape; plan 5 packages
everything.

v2 (admin lock, connector gateway, tamper-evident audit) and v3 (isolated
runner) are designed in spec §9 and get their own specs after v1 ships.
