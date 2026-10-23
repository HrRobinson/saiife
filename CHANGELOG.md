# Changelog

## Unreleased

- Audit records are now v2: each carries a sequence number and the SHA-256 of the previous line (a hash chain), plus kind, mode, host and policy. 0.1.0 can still read them.
- New `saiife audit verify` checks the chain (exit 0 intact, 1 broken, 2 unreadable).
- `saiife audit --report` gains Audit chain, Policy in force and Mode per host sections.
- `error_denied` now counts as blocked in `saiife audit`, `--blocked` and the report.
- A project `.saiife/config.toml` that is not a regular file (a FIFO or device, also when reached through a symlink) or is over 64 KiB is not read: the default packs apply, with a warning.
- A project `.saiife/config.toml` symlinked to a file outside the project is refused (never opened or quoted), by the hook and by `saiife init`; links that stay inside the project still work.
- New `saiife daemon --system` (Linux): the locked-mode daemon. It is the single writer of the audit log, stamps every record's time and identity, and signs checkpoints with an Ed25519 key.
- New `saiife check --managed` (Linux): the locked-mode hook. The guard runs in a separate worker process, and the call is allowed only after the daemon has recorded it. Every error (a worker crash or hang, a daemon that is down, slow or refuses, a policy that cannot be loaded) blocks the call: it fails closed.
- `saiife audit verify` checks checkpoint and key-rotation signatures.
- `saiife init` and `saiife status` read the project config with the same bounded, race-free read as the hook.

- New `sudo saiife system install` and `sudo saiife system uninstall` (Linux): set up or remove locked mode on Ubuntu 22.04+, Debian 12+ and RHEL 9+ (Rocky, Alma) with systemd. Install creates the `saiife` user and groups, puts the binary in `/opt/saiife/bin`, writes `/etc/saiife`, the vault key and the `saiifed` unit, adds managed hooks for Claude Code, Codex and Gemini CLI, starts the daemon and runs `saiife doctor`. Exit 2 on an install error or an unsupported system, 1 when installed but `doctor` found a failure. Uninstall removes exactly what install listed; `--purge` also removes the state, the audit and the users.
- New `saiife doctor [--user <name>] [--json]`: checks the machine locked mode relies on (files, owners and modes, keys, daemon, agent users, sudo and root-equivalent groups, plaintext credentials). Exit 0 all pass, 1 a warning, 2 a failure.
- New `core.lock` pack, on in locked mode: protects saiife's own install (`/etc/saiife`, `/opt/saiife`, the state, audit and socket dirs, the unit and the managed agent settings).
- New `saiife check --managed --event config-change`: Claude Code's ConfigChange hook. A change to user, project or local settings that sets a locked key is denied.
- Locked mode denies MCP tools whose server is not in `[guard.mcp] allow_servers`. `doctor` and `status` warn about each listed server: its requests are not brokered or limited.
- Under a managed hook, the project hook of that agent goes quiet (no double judging, no second record).
- Developer mode can opt in to fail closed with `[guard] fail = "closed"` in `/etc/saiife/config.toml`.
- `saiife status` shows a Locked mode block: mode, daemon health and chain head, policy hash, each managed agent's lock label and the MCP warnings. In locked mode `saiife init` writes no project hook for an agent with a managed hook, and `saiife init --off` keeps the project config.
- Lock labels: Claude Code is lockable; Codex and Gemini CLI are unverified (managed hooks are installed, `doctor` warns).

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
