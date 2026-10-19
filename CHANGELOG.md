# Changelog

## 0.1.0 — YYYY-MM-DD

First release.

- 13 guard packs: filesystem, git, secrets, self-protection, Docker, Kubernetes, AWS, Azure, Google Cloud, Terraform, Postgres, MySQL and MongoDB. Each has a docs page in `docs/packs`.
- Audit log of every decision, with secrets masked. Read it with `saiife audit`.
- `saiife audit --report` writes a self-contained HTML report that a non-developer can read.
- `saiife init`, `saiife init --off` and `saiife status` for Claude Code, Codex and Gemini CLI. `status` detects when a hook or config was changed.
- Agent docs in `docs/agents`, a Codex with Ollama recipe, and a demo script.
- Prebuilt binaries for Linux and macOS (Intel and ARM), and `install.sh` with checksum verification.

Known limit: the Codex and Gemini CLI hooks are not yet verified against live installs.
