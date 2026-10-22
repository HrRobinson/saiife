# Changelog

## Unreleased

- Audit records are now v2: each carries a sequence number and the SHA-256 of the previous line (a hash chain), plus kind, mode, host and policy. 0.1.0 can still read them.
- New `saiife audit verify` checks the chain (exit 0 intact, 1 broken, 2 unreadable).
- `saiife audit --report` gains Audit chain, Policy in force and Mode per host sections.
- `error_denied` now counts as blocked in `saiife audit`, `--blocked` and the report.

## 0.1.1 — 2026-10-19

- Guard: `rm` targets are judged against a `cd` earlier in the same command line (`cd / && rm -rf *` is now blocked).
- status: warns about nested `.saiife/config.toml` files that `saiife init` did not create.

## 0.1.0 — 2026-10-19

First release.

- 13 guard packs: filesystem, git, secrets, self-protection, Docker, Kubernetes, AWS, Azure, Google Cloud, Terraform, Postgres, MySQL and MongoDB. Each has a docs page in `docs/packs`.
- Audit log of every decision, with secrets masked. Read it with `saiife audit`.
- `saiife audit --report` writes a self-contained HTML report that a non-developer can read.
- `saiife init`, `saiife init --off` and `saiife status` for Claude Code, Codex and Gemini CLI. `status` detects when a hook or config was changed.
- Agent docs in `docs/agents`, a Codex with Ollama recipe, and a demo script.
- Prebuilt binaries for Linux and macOS (Intel and ARM), and `install.sh` with checksum verification.

Known limit: the Codex and Gemini CLI hooks are not yet verified against live installs.
