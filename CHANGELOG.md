# Changelog

## 0.2.0 — unreleased (waiting for red-team suite)

- Audit forwarding (Linux, locked mode): the daemon sends a copy of the audit to syslog (RFC 5424, also over TLS), to a file, or to an HTTPS endpoint (batches, Splunk HEC). Each target has its own cursor and delivery is at-least-once. Configure it with `[audit.forward.*]`. See `docs/forwarding.md`.
- New `saiife audit verify --external <file|dir>`: compares the local chain with a forwarded copy, so a cut or rewrite of records that were already forwarded shows.
- Auditors: the `saiife-audit` group reads the audit, and a per-user `audit.query` lets others query their own records through the daemon. `saiife audit` gains `--kind` and `--service`. See `docs/auditors.md`.
- New `saiife policy check|test|show|reload`: validate a policy (including overlapping scopes), run its `[[example]]` entries (exit 1 on a mismatch), print the merged policy and its hash, and reload it (admin).
- `saiife audit --report` gains sections for connectors, approvals, `error_denied`, daemon restarts and forwarding outages.
- Docs: threat coverage for each of the four setups, an egress recipe (nftables) with a `doctor` hint, forwarding and auditors pages.
- CI: the `locked-linux` job runs a locked end-to-end demo.
- Carry-over fixes from plans 10 and 11 (approval outcome in the report, open outages, section filters, stricter forward target validation, forwarder resume after a chain restart, polkit and install edge cases).

- Locked mode (Linux): approvals. A connector capability in a service's `ask` list, or a command denied by a rule in the new `[guard] ask`, waits for a person in `[approval] approvers`. `saiife api` exits 3 with the request id (`--wait` polls for the result, `saiife api result <id>` fetches it; HTTP answers 202 and `GET /v1/requests/{id}`). New `saiife approvals [show]`, `saiife approve` (`--accept-truncated`) and `saiife reject`. `same_user = "reauth"` lets one person approve their own requests through polkit (`com.saiife.approve`); the default `"deny"` needs a second account. An approved command becomes a one-use grant for that exact command in the project, for 15 minutes. At most 20 pending requests per user. See `docs/approvals.md`.
- Guard records keep `rule` (the regex) and gain `rule_id`; only `core.git`, `db.postgres` and the Kubernetes delete-namespace rule have ids in v2.0.
- New `[notify]`: webhook, SMTP and command targets for `approval_created`, `limit_reached`, `error_denied_burst`, `chain_break` and `lockdown` (`forward_failing` is defined; nothing sends it yet). Masked one-line summaries only, never a body or a secret. See `docs/notifications.md`.
- New `saiife lockdown on|off` (root, `[admin]` groups and approvers): denies connector requests, or with `--scope all` every hook call too. It survives restarts and is recorded and notified. See `docs/threats.md`.
- `saiife doctor` warns when re-authentication is unavailable.

- Locked mode (Linux) gets an encrypted vault and a connector gateway. New `saiife secret add|list|rotate|remove|import` store credentials (token, basic, header) in a vault the agent cannot read; `import` moves plaintext credentials out of a home and keeps a 7-day backup. New `saiife connect <service>` writes a deny-all policy file; with `--secret <name>` it reuses an existing secret that allows the service.
- New `saiife api <service> <operation>`: the daemon checks the call against the policy and limits, adds the vault credential, sends it and masks the answer. Connectors for Shopify, HubSpot, GitHub and a generic HTTP service; see `docs/connectors/README.md`.
- New HTTP gateway on `gateway.sock`, and an optional loopback TCP listener with `saiife api token` (12 h bearer tokens bound to your uid).
- New `saiife run --secret`: runs a command from the daemon's `run_allow` list with a leased secret in its environment, and masks its output.
- Requests per minute, writes, deletes, bulk and amount limits per service; the `connector` audit record.
- The control socket's answers may be up to 16 MiB; requests stay at 1 MiB.

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
