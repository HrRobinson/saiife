# saiife v2: design (locked + brokered)

**Date:** 2026-10-19
**Status:** approved for planning, pending the owner's read-through
(amended 2026-10-19 with the owner's decisions and the builder's answers, §0)
**Builds on:** v0.1.0 (v1: guard + audit), released 2026-10-19
**Parent spec:** `2026-10-13-saiife-cli-v1-design.md` (§1.1 product ladder,
§1.2 principles, §7, §9). Section references like "v1 §9.2" point there.
**License:** FSL-1.1-ALv2, unchanged.

Items marked **(proposed addition)** go beyond v1 §9.1–9.3 and §9.5. Each one
gives a one-line reason, so the owner can veto it. §16.1 says which of them
ship in v2.0 and which come later. Everything else either implements v1 §9
or is a design detail it needs.

## 0. Decisions after review (2026-10-19)

The owner answered the open questions of the first draft, and the controller
answered a builder check. Both are binding on this spec. The sections they
touch say so where they apply.

| # | Decision | Label | Applies in |
|---|---|---|---|
| 1 | v2.0 includes these proposed additions: `saiife doctor`, the `core.lock` pack, command approvals (`[guard] ask`), notifications, `saiife lockdown`, amount caps, `saiife policy check`/`test`. These come **after v2.0**: `saiife mcp`, the MCP gateway, fleet packages and MDM recipes. Response field redaction and the egress recipe were left to the designer: both stay in v2.0, because each fits into an existing plan for about one evening (redaction is one more step in the masking pass of plan 10; the recipe is one docs page in plan 12). | Owner decision (2026-10-19); last sentence: designer's call | §6, §15, §16.1 |
| 2 | Linux first. In v2.0, locked mode is **Linux only**. macOS locked mode (Developer ID, hardened runtime, notarization, launchd, `LOCAL_PEERCRED`, macOS re-authentication) moves to **v2.1**. Macs keep v1 developer mode in v2.0. | Owner decision (2026-10-19) | §1.1, §5.3, §14, §15 |
| 3 | Same-user approvals: re-authentication through polkit ships in v2.0. Without polkit, only a second uid can approve, and `doctor` says so. | Owner decision (2026-10-19) | §6.10.2, §6.16 |
| 4 | First-wave connectors stay Shopify, HubSpot, GitHub and generic HTTP. Writes are allowed under policy, with `ask` and amount caps available. | Owner decision (2026-10-19) | §6.8.3 |
| 5 | The model-provider key is **not brokered** in v2. The agent holds its own model login, or uses a local model (for example Ollama). "The agent never holds a credential" excludes the model login, and the docs say so. | Owner decision (2026-10-19) | §1, §1.3, §10 |
| 6 | One `[[scope]]` per uid. A uid that matches two scopes is a config error: `policy check` fails and the daemon refuses to load the policy. `projects` is attribution only and never selects an environment or a scope. | Builder's call (controller) | §6.9.1, §6.11, §8.1 |
| 7 | Personal broker mode moves after v2.0. It stays designed (§6.6) as a later item. | Builder's call (controller) | §1.1, §15 |
| 8 | Supported systems for v2.0 locked mode: Ubuntu 22.04+, Debian 12+, RHEL 9+, with systemd required. With systemd older than 250 (no `LoadCredentialEncrypted`; Ubuntu 22.04 ships 249), the vault key is a root-owned file that only the daemon user can read. `SO_PEERPIDFD` is optional, with `SO_PEERCRED` as the fallback. A TPM is optional. Alpine and containers get developer mode only. | Builder's call (controller) | §1.1, §5.2, §5.4.1, §6.3 |
| 9 | Plan 7 gate rule: an agent that fails the live lock checks is labelled **"not lockable"**, and v2.0 ships for the others. Gemini CLI's label follows the same rule. | Builder's call (controller) | §6.1.3, §14 |
| 10 | MCP before the gateway exists: locked mode allows only MCP servers the admin lists in policy. These are not brokered, and `status` and `doctor` warn that they bypass saiife. | Builder's call (controller) | §6.1.4, §6.16, §9.2 |

The v1 track already uses "plan 6" (v0.1.1, v1 gaps), so the v2 plans start
at plan 7 (§15).

## 1. Purpose

v2 makes saiife safe for agents that **run unattended** on company machines:
nobody is watching each tool call, and nobody is around to notice a broken
guard. In v1 §1.1 terms:

- **Locked:** the agent cannot turn saiife off, cannot change its policy, and
  cannot edit or delete the audit trail. That holds against a script the
  agent writes and runs as its own OS user, not only against the agent's
  tool calls.
- **Brokered:** the agent never holds a credential for an external service.
  It reaches HubSpot, Shopify, GitHub, clouds and the rest only through the
  saiife gateway, and only under per-service rules (deny by default). Every
  request is audited. **One exception, by design:** the agent's own login to
  its model provider (Anthropic, OpenAI, Google) is not brokered in v2. The
  agent holds it, or the company runs a local model such as Ollama and there
  is no key (owner decision 5, §0).

v2 also brings back every localflow feature that v1 §9.5 puts in v2:
connectors, the agent-facing API client with collections, per-session cloud
credentials, and environments.

### 1.1 Setups v2 supports

| Setup | Who installs | Agent runs as | Meant for | Platforms |
|---|---|---|---|---|
| **Developer** (v1 mode, still the default) | the developer, no root | the developer | a person nearby; same guarantees as v1 plus a hash-chained log | v2.0: Linux (any, including Alpine and containers) and macOS |
| **Personal broker** (after v2.0, decision 7) | the developer, no root | the developer | trying connectors on your own machine; **not a security boundary** (§10) | later |
| **Locked** | an admin, as root | the person's own account | company laptops and workstations, attended or unattended | v2.0: Linux only (Ubuntu 22.04+, Debian 12+, RHEL 9+, systemd required). macOS in v2.1. |
| **Locked, dedicated agent account** (recommended for unattended) | an admin, as root | an OS account that exists only for agents (for example `agent-shop`) | unattended agents on servers or shared machines | as Locked |

Alpine, other non-systemd Linux systems and containers get developer mode
only (decision 8). `saiife system install` refuses them with a clear message.
Macs keep v1 developer mode in v2.0 (decision 2). macOS-specific parts of
this spec (§5.3, the macOS halves of §6.3 and §6.10.2) are designed now and
built in v2.1.

The last setup is not v3 isolation: saiife does not start or sandbox the
agent, and there is no egress control. It is an admin choice that v2
documents and checks (`saiife doctor`), because it removes the human's own
files and logins from what the agent can reach.

### 1.2 Threat model delta

v1 §1.1 names three threats. v2 changes the coverage as follows (§10 has the
full per-setup table):

| Threat | v1 | v2 locked |
|---|---|---|
| Mistake | covered by packs; fails open | covered by packs; **fails closed** |
| Helpful bypass (agent turns saiife off or edits its config) | discouraged by `core.self`, detected by `status` | **prevented**: hook config, binary, policy, audit and vault are not writable by the agent's OS user |
| Determined bypass: get a credential | not covered | **covered for brokered services**: the credential is not on the machine in a form the agent's user can read (once migrated, §12). **Not** the agent's own model-provider login, which it keeps (owner decision 5). |
| Determined bypass: use an external service beyond the rules | not covered | **covered**: no key outside the gateway, so the only working path goes through policy, limits and approval |
| Determined bypass: erase or rewrite the audit trail | not covered | **covered** against the agent's user; detected against root once logs are forwarded |
| Determined bypass: run local code outside the hook (script, patched or nested agent) | not covered | **still not covered.** That code has no keys, cannot touch saiife and is not audited. This is v3 (isolated runner). |
| Data exfiltration to an arbitrary host | not covered | **still not covered** (v3 egress control). A docs recipe narrows it for dedicated accounts (§6.20). |

The rule behind the table: v2 moves the *valuable* things (keys, policy,
audit, the hook itself) out of the agent's OS identity. It does not confine
the agent's *own* code. That is v3.

### 1.3 Principles (v1 §1.2) applied to v2

1. **Defense in depth.** v1 packs stay on in every mode, including
   `core.secrets` and `core.self`, even where file permissions already stop
   the action. The broker does not replace the guard, and the guard does not
   replace file permissions.
2. **The agent never holds what it must not misuse.** Credentials live in a
   vault owned by a separate OS user. The two places where the agent still
   holds a service credential are opt-in and labelled: `saiife run --secret`
   (§6.14) and STS mode for cloud credentials (§6.13). The agent's own
   model-provider login is outside this rule in v2 (owner decision 5): it
   holds that login, or uses a local model.
3. **Deny by default for capabilities.** Connector operations, MCP tools in
   locked mode, approvers and scopes are all denied unless allowed. Commands
   stay allow-by-default (the guard), as in v1.
4. **Fail open only where a human is present.** Developer mode keeps
   failing open. Locked mode fails closed (§9.3 lists the exceptions the
   agents' hook contracts force on us).
5. **Protection must be observable.** Every `error_denied`, every daemon
   restart, every forwarding outage and every gap in the chain is a record.
   `saiife doctor` reports host conditions that weaken the lock.
6. **The audit trail must outlive the agent.** Written only by the daemon's
   OS user, hash-chained, signed checkpoints, optionally forwarded off the
   machine.
7. **Offline and local by default.** At runtime, saiife makes network calls
   only for (a) connector traffic to services the admin configured,
   (b) audit forwarding the admin turned on, (c) approval notifications the
   admin turned on. All three are off until configured, and all three are
   audited. No telemetry, no update check.

### 1.4 Not in v2

- Starting agents, sandboxes, egress control, `saiife sessions`, flows and
  the OpenClaw operator. These are v3 (v1 §9.4, §9.5).
- A central multi-machine dashboard (after v3).
- Windows.
- Signed policy bundles, a local web dashboard and transcript redaction:
  considered and cut (§16.2).
- Brokering the agent's model-provider key (owner decision 5).

Designed here, but shipped after v2.0 (§15): macOS locked mode (v2.1),
personal broker mode, `saiife mcp`, the MCP gateway, fleet packages and MDM
recipes, connector waves 2 and 3, cloud connectors, environments and
collections.

## 2. Decisions

| # | Decision | Chosen | Why |
|---|---|---|---|
| D8 | Privileged component | A long-running daemon, `saiifed`, running as a **dedicated unprivileged system user** (`saiife` on Linux, `_saiife` on macOS). Root is needed only to install it. | Least privilege. A setuid helper adds a root attack surface on every hook call and is awkward on macOS. A root daemon parses agent input as root. §5.5. |
| D9 | IPC | Unix domain sockets in a directory owned by the daemon user. Callers are identified by kernel peer credentials (uid, pid). No TCP by default. | Loopback TCP cannot tell callers apart. A socket path the agent's user cannot create cannot be spoofed. |
| D10 | Where guard decisions are made | In the hook process, as in v1. The daemon writes the record and acknowledges it before the hook answers. | Path checks need the agent user's view of the filesystem. A forged client gains nothing it could not get by skipping the hook (§9.4). Keeps the 50 ms budget. |
| D11 | Locked-mode failure | Fail closed: any error, missing acknowledgement from the daemon, or exceeded budget means deny and `error_denied`. | v1 §1.2 rule 4. |
| D12 | Lock location | Hooks go into each agent's system-level policy file (managed settings). The binary goes in `/opt/saiife/bin/saiife`, and the hook calls it by absolute path. | v1 §9.1. On macOS with Homebrew, `/usr/local/bin` is often owned by the user, so it cannot hold a locked binary. |
| D13 | Vault | A file encrypted at rest, owned by the daemon user (locked mode). The OS keychain is used in personal broker mode (after v2.0). | The OS keychain's per-user model cannot keep a secret from the same user's processes. |
| D14 | Connector shape | Declarative TOML manifests embedded in the binary (like packs). Operations are typed and map to capabilities (`orders:read`). A generic HTTP connector covers the rest. | Manifests are reviewable, testable without network, and cheap to add (about 1 evening each for most services). |
| D15 | Agent access to connectors | v2.0: `saiife api` on the command line and an HTTP gateway on a Unix socket (`curl --unix-socket`, SDKs via proxy paths). After v2.0: an MCP server **(proposed addition)**. | The CLI works for every agent today. HTTP lets existing SDKs work. MCP is how agents prefer to call tools. |
| D16 | Approvals | `ask` rules create a request. The agent gets "pending #N" right away and never waits inside a hook. Only an approver identity the agent's user cannot be can decide (§6.10). | Hooks have timeouts. An approval the agent could give itself is worthless. |
| D17 | Audit format | JSONL, `v = 2`, one global hash chain per machine (`seq`, `prev`), signed checkpoints, v1 fields kept so 0.1.0 readers still work. | v1 §9.3. |
| D18 | State store | Files only (JSON and JSONL), no database. Rate-limit counters are rebuilt from the audit log at startup. | Keeps the static musl build and the "one binary" rule (v1 D4). The audit log is the source of truth. |
| D19 | One binary | Still one `saiife` binary. `saiife daemon` is a subcommand. | v1 D4. Install and upgrade stay one file. |
| D20 | Scope of a caller | Authorization is by **OS user** (uid), through exactly one `[[scope]]` per uid (decision 6). Project paths and agent sessions are used for attribution and limits only; they never select a scope or an environment. | uid is the only identity the kernel vouches for in v2. v3 adds runner-issued session identity. |
| D21 | Platforms for locked mode | v2.0: Linux with systemd (Ubuntu 22.04+, Debian 12+, RHEL 9+). v2.1: macOS. | Owner decision 2, builder's call 8. One service manager and one peer-credential API to get right first. |

## 3. What exists today (v0.1.0)

- `crates/guard`: lexer, engine, path rules, 13 packs (`core.filesystem`,
  `core.git`, `core.secrets`, `core.self` on by default; 9 opt-in).
- `crates/audit`: `Record` v1, masking, month files in the user's data dir
  (0700 dir, 0600 files), `read_all`/`read_recent`, unknown decision values
  kept as `Unknown`.
- `crates/agents`: per-agent install and remove of project hooks, JSON and
  TOML edits that keep key order, integrity records, fingerprints.
- `crates/cli`: `init`, `init --off`, `status`, `check`, `test`, `explain`,
  `packs`, `audit`, `audit --report`.
- Hooks: project-level, called through `PATH` as `saiife check --hook-exit
  --agent <name>`, with a timeout of 10 s. Every failure fails open and is
  recorded as `error_allowed`.

Open carry-over items from the v1 roadmap that v2 takes over:

| Carry-over | Where v2 handles it |
|---|---|
| Engine abort or stack overflow is not caught (only panics) | Locked mode runs the evaluation in a worker process (§6.1). |
| Payloads over 1 MiB are logged with empty input (shell fields) | Locked mode denies a payload it cannot read in full, as `error_denied` (§6.1). |
| Codex `requirements.toml` path and `allow_managed_hooks_only` not checked | Plan 7 checks this live; `doctor` and `status` check it (§6.16). |
| Gemini hooks on/off setting unknown | Plan 7 checks this live. Gemini's lock label follows the gate rule (§6.1.3, decision 9). |
| Codex and Gemini not run against a live install | Plan 7 is a gate for all of v2: managed settings for all three agents verified live and stored as fixtures. |
| The report shows packs as configured today, not as they were | Each record carries `policy` (a hash of the effective policy), plus a `policy` record whenever it changes (§8.5). |
| The report file is 0600 | Auditors group and `saiife audit` through the daemon (§6.4.5). |
| Claude Code `ConfigChange` hook not used | Used in the managed hook set, to record and block settings changes made outside tool calls (§6.1.1). |
| A nested `.saiife/config.toml` with `packs = []` turns opt-in packs off | In locked mode, project config can only add (§8.2). |
| `off()` wording; `time` macros as a cli dev-dependency; pin `Swatinem/rust-cache` to a SHA; check the first `release.yml` dry-run | Plan 7 housekeeping. |
| `cd` is not tracked (`cd / && rm -rf *`) | Unchanged in v2. Listed in §10. |

## 4. Architecture

### 4.1 Process model

```
 agent process (uid alice)                         saiifed (uid saiife)
 ┌──────────────────────┐   hook    ┌────────────┐  saiife.sock  ┌─────────────────────────┐
 │ claude / codex /     │─────────▶ │ saiife     │──────────────▶│ control server          │
 │ gemini               │ stdin/exit│ check      │ audit.append  │  ├ audit writer (1 task)│──▶ /var/log/saiife/audit/*.jsonl
 │                      │           │ (+ worker) │◀────── ack ───│  ├ approvals            │──▶ /var/lib/saiife/approvals/
 │  Bash tool ─▶ shell ─┼─▶ saiife api ───────────────────────▶│  ├ policy (from /etc)   │◀── /etc/saiife/*.toml (root)
 │                      │           │            │               │  ├ limits (in memory)   │
 │  SDK / curl ─────────┼──────────────────────── gateway.sock ─▶│  └ vault                │──▶ /var/lib/saiife/vault/
 └──────────────────────┘                                        │ gateway (HTTP/1.1)      │
                                                                 │  └ connector workers ───┼──▶ https://api.hubspot.com …
                                                                 │ forwarder ──────────────┼──▶ syslog / SIEM (optional)
                                                                 │ notifier ───────────────┼──▶ webhook / SMTP (optional)
                                                                 └─────────────────────────┘
```

- **Hook path** (every tool call): the agent spawns `/opt/saiife/bin/saiife
  check --managed --hook-exit --agent <a>`. The client reads the payload,
  evaluates it in a worker child (same binary, `__eval`), builds the masked
  record, sends `audit.append` to the daemon, waits for the acknowledgement
  (sequence number), then answers the agent. No ack within 2 s means deny.
- **Connector path:** `saiife api …`, the gateway socket, or `saiife mcp`
  sends a request to the daemon. The daemon checks scope, policy, limits and
  approvals, attaches the credential, calls the upstream, masks the response,
  writes one record and returns the result.
- **Admin path:** root (through `sudo`) or a member of the configured admin
  group edits `/etc/saiife/`, then runs `saiife policy reload` (or sends
  SIGHUP). Secrets go in through `saiife secret add` over the socket. The
  daemon checks the peer's uid for every admin operation.

The daemon is a tokio process with one runtime. The audit writer is one task
fed by a bounded channel, so records are ordered and the chain needs no
locks. Connector calls run on a bounded pool per service (default 4 at a
time).

### 4.2 Crates

```
crates/
  guard/    unchanged engine; packs gain core.lock (proposed); rules gain an "ask" action (proposed)
  audit/    Record v2, chain (hash, verify, checkpoint), masking, readers that accept v1 and v2
  agents/   project hooks (v1) + managed hook install/verify per agent
  policy/   NEW: /etc + project config parsing, merge, effective-policy hash, scopes, environments
  ipc/      NEW: frame codec, op types, blocking client (std UnixStream, no tokio), peer creds
  broker/   NEW: connector manifests (connectors/*.toml, embedded), capability matching,
            limits, request building, response masking, HTTP client (hyper + rustls)
  daemon/   NEW: saiifed: control server, gateway, audit writer, vault, approvals,
            forwarder, notifier, service-manager integration
  cli/      the saiife binary; new commands in §7
```

`guard`, `audit` and `policy` stay free of tokio and networking, so the hook
path (`check`) stays small and fast. Only `broker` and `daemon` link tokio,
hyper and rustls. New dependencies: `tokio`, `hyper`, `hyper-util`,
`rustls`, `rustls-native-certs`, `ed25519-dalek`, `chacha20poly1305`,
`zeroize`, `rustix` (peer credentials), `base64`, `uuid`. The expected
binary growth is about 3–4 MB. Startup cost of `check` must stay within the
v1 bench (`scripts/bench-check.sh`, gate in §13).

## 5. Privilege model

### 5.1 Identities

| Identity | What it is | May |
|---|---|---|
| **root / admin** | root, or a uid in `[admin] groups` (default: none besides root) | install, edit `/etc/saiife`, add and remove secrets, reload policy, uninstall |
| **daemon user** | `saiife` (Linux, system uid) / `_saiife` (macOS, uid < 500, hidden) | own state, vault, keys, audit files; open connector and forwarding connections. No login shell, no home, no sudo. |
| **auditor** | members of group `saiife-audit` (`_saiifeaudit` on macOS) | read all audit files, run `audit verify` and the full report |
| **approver** | uids listed in `[approval] approvers` (users or `group:` entries) | decide `ask` requests |
| **agent user** | any other uid (the developer, or a dedicated agent account) | send hook records, call connectors allowed by its scope, read its own audit records, see its own pending requests |

One uid can hold several roles, with one exception that saiife enforces: a
uid can never approve requests created by itself, unless
`[approval] same_user = "reauth"` (§6.10).

### 5.2 Files and permissions: Linux

| Path | Owner:group | Mode | Contents |
|---|---|---|---|
| `/opt/saiife/` and `/opt/saiife/bin/` | root:root | 0755 | |
| `/opt/saiife/bin/saiife` | root:root | 0755 | the binary (static musl) |
| `/usr/local/bin/saiife` | root:root | symlink | optional, for people's shells; hooks never use it |
| `/etc/saiife/` | root:root | 0755 | |
| `/etc/saiife/config.toml` | root:root | 0644 | system config (§8.1) |
| `/etc/saiife/policy.d/*.toml` | root:root | 0644 | drop-ins, read in name order (one per service is the convention) |
| `/etc/saiife/ca/*.pem` | root:root | 0644 | optional company CA certificates for upstream and SIEM TLS |
| `/etc/saiife/credstore/vault-key` | root:root (systemd ≥ 250) / root:saiife (systemd < 250) | 0600 / 0640 | vault key: an encrypted systemd credential, or a plain key only the daemon user can read (note below) |
| `/etc/saiife/installed.toml` | root:root | 0644 | what `system install` wrote, with SHA-256 fingerprints (managed hook files, unit file, binary) |
| `/etc/systemd/system/saiifed.service` | root:root | 0644 | unit (§5.4.1) |
| `/var/lib/saiife/` | saiife:saiife | 0700 | daemon state (systemd `StateDirectory`) |
| `/var/lib/saiife/vault/vault.bin` | saiife:saiife | 0600 | encrypted vault (§8.9) |
| `/var/lib/saiife/keys/audit.ed25519` | saiife:saiife | 0600 | checkpoint signing key |
| `/var/lib/saiife/approvals/<id>.json` | saiife:saiife | 0600 | approval requests (§8.10) |
| `/var/lib/saiife/state/` | saiife:saiife | 0700 | forwarding cursors, lockdown flag, limit snapshots |
| `/var/log/saiife/audit/` | saiife:saiife-audit | 2750 | |
| `/var/log/saiife/audit/YYYY-MM.jsonl` | saiife:saiife-audit | 0640 | the chain |
| `/run/saiife/` | saiife:saiife | 0755 | (systemd `RuntimeDirectory`) |
| `/run/saiife/saiife.sock` | saiife:saiife | 0666 | control socket; access decided per uid by the daemon |
| `/run/saiife/gateway.sock` | saiife:saiife | 0666 | HTTP gateway socket |
| `/etc/claude-code/managed-settings.d/50-saiife.json` | root:root | 0644 | Claude Code managed hooks (§8.3) |
| `/etc/codex/requirements.toml` | root:root | 0644 | Codex managed hooks; path verified live in plan 7 |
| `/etc/gemini-cli/settings.json` | root:root | 0644 | Gemini CLI system settings |

The vault key (builder's call 8):

- **systemd 250 or later** (Debian 12, RHEL 9, Ubuntu 24.04): systemd passes
  it in as an encrypted credential (`LoadCredentialEncrypted=vault-key`,
  from `/etc/saiife/credstore/vault-key`). It is bound to the TPM when there
  is one, and to the host key otherwise. A TPM is optional.
- **systemd older than 250** (Ubuntu 22.04 ships 249): a plain key file,
  `/etc/saiife/credstore/vault-key`, owned by root, group `saiife`, mode
  0640. The `saiife` group has no other member, so only root and the daemon
  user can read it. The unit uses `LoadCredential=` (systemd 247+) instead.
  `doctor` reports which of the two is in use.

The encryption protects backups and disk images. On a running machine, the
file permissions are the barrier.

### 5.3 Files and permissions: macOS (v2.1)

Not built in v2.0 (owner decision 2): Macs run developer mode until v2.1.
The layout is fixed now so that v2.0 does not block it. Same layout as
Linux, with these differences:

| Linux | macOS |
|---|---|
| user `saiife`, group `saiife-audit` | `_saiife` and `_saiifeaudit`, created with `dscl` (uid/gid from the 200–400 range, `IsHidden = 1`, shell `/usr/bin/false`) |
| `/var/lib/saiife` | `/var/db/saiife` (0700 `_saiife`) |
| `/run/saiife` | `/var/run/saiife` (created by the daemon at start; `/var/run` is cleared at boot) |
| systemd unit | `/Library/LaunchDaemons/com.saiife.saiifed.plist` (root:wheel 0644), `UserName = _saiife`, `KeepAlive = true`, `RunAtLoad = true` |
| `LoadCredentialEncrypted` | `/var/db/saiife/keys/vault.key` (0400 `_saiife`) |
| Claude managed settings | `/Library/Application Support/ClaudeCode/managed-settings.json` (and `managed-settings.d/` if live check confirms drop-ins on macOS) |
| Gemini system settings | `/Library/Application Support/GeminiCli/settings.json` |
| Codex | `/etc/codex/requirements.toml` (unverified on macOS; plan 7) |
| peer credentials | `getsockopt(LOCAL_PEERCRED)` for the uid, `LOCAL_PEERPID` for the pid |
| process ancestry | `sysctl(KERN_PROC_PID)` (readable for all users) |

`/etc/saiife` resolves to `/private/etc/saiife`. That is fine for MDM tools,
and it keeps one path in the docs on both platforms.

macOS release binaries must be signed with a Developer ID and the hardened
runtime, and notarized. The hardened runtime makes the binary ignore
`DYLD_INSERT_LIBRARIES` (an agent could otherwise inject code into a nested
hook process), and Gatekeeper and MDM tools expect signed launch daemons.
This is v2.1 work (owner decision 2).

### 5.4 How the lock holds

The lock rests on four facts the kernel enforces, not on the guard:

1. **The agent's user cannot write** the binary, its parent directories,
   `/etc/saiife`, the managed agent settings, the daemon's state, the vault
   or the audit files. These are owned by root or by the daemon user, with
   no group or world write.
2. **The agent's user cannot signal or trace the daemon.** It runs as
   another uid. `kill`, `ptrace` and `/proc/<pid>/mem` all need the same uid
   or `CAP_KILL`/`CAP_SYS_PTRACE`.
3. **The agent's user cannot become root or the daemon user.** This is a
   host precondition, not something saiife can enforce. `saiife doctor`
   checks it (§5.6).
4. **The agent cannot remove the managed hook from its own agent session.**
   Managed settings outrank user, project and command-line settings in all
   three agents (Claude Code: verified in research; Codex: managed
   requirements pin `[features] hooks = true`; Gemini CLI: system settings
   win in code). Plan 7 confirms each against a live install, including that
   a user-level `disableAllHooks` cannot switch off a managed hook.

Everything the guard does in locked mode (`core.self`, `core.lock`) is the
extra layer on top (principle 1). It turns attempts into clear denials and
audit records instead of permission errors.

#### 5.4.1 systemd unit (Linux)

```ini
[Unit]
Description=saiife daemon (audit, vault, connector gateway)
After=network-online.target

[Service]
Type=notify
User=saiife
Group=saiife
ExecStart=/opt/saiife/bin/saiife daemon --system
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=1
StateDirectory=saiife
StateDirectoryMode=0700
RuntimeDirectory=saiife
RuntimeDirectoryMode=0755
LogsDirectory=saiife/audit
LogsDirectoryMode=2750
UMask=0027
LoadCredentialEncrypted=vault-key:/etc/saiife/credstore/vault-key
# systemd < 250: LoadCredential=vault-key:/etc/saiife/credstore/vault-key (§5.2)
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
CapabilityBoundingSet=
LimitCORE=0

[Install]
WantedBy=multi-user.target
```

`ProtectHome=yes` is deliberate: the daemon never needs to read people's
home directories. The daemon also calls `prctl(PR_SET_DUMPABLE, 0)` and
keeps secret bytes in `zeroize` buffers.

### 5.5 Alternatives considered

| Option | Verdict |
|---|---|
| setuid-root helper for audit writes (v1 §9.1 option) | Rejected: root code runs on every hook call with an environment the agent controls; macOS discourages setuid; no place to hold connector state. |
| Root daemon | Rejected: parses agent input and talks to the internet as root. The daemon needs no root rights after install. |
| **Separate-user daemon** | **Chosen.** Root only at install. The kernel separates the daemon from the agent's user. |
| Per-user daemon (systemd `--user`, LaunchAgent) | Kept only for personal broker mode. Same uid as the agent, so no boundary. |
| Linux LSM, Landlock or seccomp confinement of the agent | v3 (isolated runner). v2 does not confine the agent's own processes. |

### 5.6 Host preconditions (checked by `saiife doctor`)

Locked mode is only as strong as these. `doctor` reports each one as pass,
warn or fail, for each agent user named in a scope:

- The agent user cannot get root without a password: `sudo -n true` fails;
  no `NOPASSWD` rule; not in `docker`, `lxd`, `incus`, `libvirt` or `disk`
  (each is root-equivalent); on macOS, not an admin without a password.
- Every directory from `/` down to `/opt/saiife/bin/saiife`, and
  `/etc/saiife`, is owned by root and not group- or world-writable.
- The daemon runs as the daemon user, and both sockets are owned by it.
- The managed hook files exist and match `installed.toml`.
- Agent versions meet the minimums (Claude Code ≥ 2.1.295 for `onFailure:
  "block"`).
- **Agent binaries are not writable by the agent user.** A user-installed
  agent (for example the Claude Code native installer in the home folder, or
  a user-level `npm -g` prefix) is a warning: a determined agent can patch
  its own program and skip hooks. The docs recommend a system-wide agent
  install for locked machines.
- `/proc` is not mounted with `hidepid` in a way that hides agent processes
  from the daemon (session attribution, §6.9.3).
- No plaintext credentials remain in the agent user's reach (§6.16).

## 6. Components

### 6.1 Locked hook path

#### 6.1.1 Managed hook entries

`saiife system install` writes the managed hook files (exact contents in
§8.3). Differences from v1 project hooks:

- **Absolute path:** `/opt/saiife/bin/saiife`, not a `PATH` lookup. This
  changes v1 §5.2, where `PATH` kept upgrades simple. In locked mode the path
  is fixed by the installer, and `PATH` belongs to the agent's user.
- **All tools:** the matcher covers every tool (`*` or `.*`). Every tool call
  is audited, which closes v1's "web fetch and MCP tools are not sent to
  saiife" gap for visibility. Tools the guard does not judge are recorded as
  `allow` with reason `tool not judged`, except for MCP tools (§6.1.4).
- **Fail closed:** Claude Code entries set `onFailure: "block"`.
- **Claude Code `ConfigChange` hook:** records every settings change made
  during a session and denies changes that touch `hooks`, `disableAllHooks`,
  `permissions`, `env` or `apiKeyHelper` in user, project or local settings.
  (Managed hooks already outrank these. This turns an attempt into a record.)
- `--managed` tells `check` it was called by a managed hook: it then ignores
  `SAIIFE_*` variables, reads `/etc/saiife/config.toml`, and requires the
  daemon.

When `/etc/saiife/installed.toml` says an agent has a managed hook, a
project-level hook for that agent (left over from v1) exits 0 silently
without a record, so each call is judged and recorded once. For an agent with
no managed hook, the project hook keeps working as in v1.

#### 6.1.2 `check` in locked mode

```
read stdin (no size cap for path fields, as v1; a shell payload over 1 MiB → deny, error_denied)
load /etc/saiife/config.toml + policy.d + project .saiife/config.toml (add-only merge, §8.2)
if lockdown == "all"                         → deny, record
spawn worker: /opt/saiife/bin/saiife __eval  (payload on a pipe; worker has the 50 ms budget)
  worker crash / signal / no answer in 3 s    → deny, error_denied
if decision == ask (proposed, §6.10.4)       → grant.consume or approval.create → allow or deny
build Record v2 (masked)                      → audit.append over saiife.sock
  no ack in 2 s, or daemon refuses           → deny, error_denied (record left with the client: stderr only)
answer the agent: exit 0 silent (allow) | exit 2 + stderr reason (deny)
```

The worker costs a fork and exec (about 2–5 ms). It turns an abort or a
stack overflow in the engine, which v1 cannot catch, into a clean
`error_denied`. The latency target is p95 under 40 ms per hook call on the
bench machine (v1 is about 16 ms).

#### 6.1.3 Lockability per agent

| Agent | Managed location | Can the user switch the managed hook off? | Fail closed on saiife error | v2 status |
|---|---|---|---|---|
| Claude Code | `managed-settings.d/50-saiife.json` | No, managed outranks all (confirm for `disableAllHooks` in plan 7) | Yes (`onFailure: "block"`, ≥ 2.1.295) | **lockable** |
| Codex | `requirements.toml` | No, `[features] hooks = true` pin; managed hooks skip trust review | Only for errors saiife reports (exit 2 + stderr). Timeout, crash or missing binary fail open in Codex. | **lockable, fail-open gaps listed** |
| Gemini CLI | system `settings.json` | No by settings, but `GEMINI_CLI_SYSTEM_SETTINGS_PATH` lets a **new** Gemini process skip the system file | Exit 2 blocks; a timeout fails open | **lockable with caveats** if it passes the plan 7 checks, otherwise "not lockable" (decision 9) |

**Gate rule (builder's call 9).** Plan 7 runs the live lock checks for each
agent on a supported Linux system: the managed hook fires; user, project and
command-line settings cannot switch it off; and the fail-closed cells of §9.3
marked "blocked" hold. An agent that fails any of them is labelled **"not
lockable"** in `status`, `doctor` and its docs page, and v2.0 ships for the
others. A "not lockable" agent still gets its managed hook (it records and
denies what it can), but no lock claim is made for it. Gemini CLI follows the
same rule. Its known environment override is a caveat, not a failure, because
it needs a new process started by a script (the A21 class), not a change to
the running session.

A nested agent started with a different system-settings path is the
"nested or patched agent" case in §10: the running session stays hooked, and
`core.self` denies the command line that does it. A script can still do it.

#### 6.1.4 MCP tools in locked mode

MCP tools (`mcp__<server>__<tool>` in Claude Code and Codex,
`mcp_<server>_<tool>` in Gemini) grant capabilities, so they are denied by
default in locked mode (principle 3):

```toml
[guard.mcp]
# Builder's call 10: in v2.0, only MCP servers listed here may be used.
# They are NOT brokered: each keeps its own credentials and talks to its
# service directly, outside saiife's policy, limits and audit of requests.
allow_servers = ["linear", "sentry"]
# Every tool call to them is still hooked and audited as a guard record.
# Tools of any other server (mcp__<server>__* / mcp_<server>_*) are denied.
```

Each listed server is an explicit gap. `status` prints one warning per
listed server ("MCP server linear bypasses saiife: its requests are not
brokered or limited"), and `doctor` reports it as a warning, with the config
file that holds the server's token if it can find one. After v2.0, the MCP
gateway (§6.15) lets an admin move a server behind the broker, and the
warning goes away for that server.

Admins can also restrict which MCP servers an agent may configure, through
the agents' own managed settings (Claude Code managed MCP settings, Codex
requirements). `system install --mcp-allow <list>` writes them where the
live check in plan 7 confirms the keys, so the list in `[guard.mcp]` and the
agents' own lists agree.

### 6.2 Daemon (`saiifed`)

- **Start:** loads policy (an invalid policy at start means "deny all
  connector calls, accept audit", recorded as `daemon`/`policy_invalid`),
  opens the audit chain (verifies the last 1 000 records and the last
  checkpoint), rebuilds rate-limit counters from the connector records of the
  last 24 h, binds both sockets, then tells systemd it is ready.
- **Reload** (SIGHUP or `policy reload`): parses, validates and swaps the
  policy in one step. An invalid new policy is refused, the old one stays,
  and a `policy` record with `result = "rejected"` is written.
- **Stop:** writes a `daemon`/`stop` record and a checkpoint.
- **Crash:** systemd and launchd restart it. At start, the daemon writes
  `daemon`/`start` with `previous_clean_stop = false` when the last record is
  not a stop record. Hook calls made while it was down were denied (fail
  closed). They show up as `error_denied` lines on the agent's side only,
  because nobody could write them.
- **Back-pressure:** each uid may have at most 64 requests in flight and
  1 000 audit appends per second. Over that, the daemon answers `busy` and
  the hook denies. When free space on the audit volume falls below
  `[audit] min_free_mb` (default 512), appends from agent users are refused
  and every hook denies. A full disk stops agents instead of silently losing
  records.

### 6.3 IPC

Control socket `saiife.sock`: frames of a 4-byte big-endian length followed
by UTF-8 JSON, at most 1 MiB per frame. The first frame is `hello`. Each
request has an `id`. Answers carry the same `id`. Details in §8.7.

The client checks before sending anything that the socket and its directory
are owned by the daemon user named in `/etc/saiife/config.toml`. In locked
mode the socket path is fixed (`SAIIFE_SOCKET` is ignored).

The daemon reads the peer's uid and pid from the kernel: `SO_PEERCRED` on
every supported Linux, plus `SO_PEERPIDFD` where the kernel has it (6.5+) to
avoid pid reuse during the process-tree walk. Without it, the daemon falls
back to `SO_PEERCRED` alone and checks the pid's start time before and after
the walk (builder's call 8). macOS (v2.1) uses `LOCAL_PEERCRED` and
`LOCAL_PEERPID`. The uid is the only authenticated fact. The pid is
used for attribution only.

Gateway socket `gateway.sock`: plain HTTP/1.1 (§8.8). An optional loopback
TCP listener (`[gateway] tcp = "127.0.0.1:7431"`, off by default) exists for
clients that cannot use Unix sockets. It requires a bearer token from
`saiife api token` (bound to the uid, valid for 12 h, stored hashed by the
daemon).

### 6.4 Tamper-evident audit

#### 6.4.1 Chain

- One chain per machine, across month files. `seq` starts at 0 and goes up
  by one per record.
- `prev` is the lowercase hex SHA-256 of the **exact bytes of the previous
  line**, without its newline. Hashing bytes instead of re-serialized JSON
  means no canonical JSON is needed, and any byte change is caught.
- Record 0 is `kind = "genesis"`, with `prev` set to 64 zeros, a random chain
  id (UUID v4), the host id (SHA-256 of `/etc/machine-id` or the macOS
  `IOPlatformUUID`, never the raw value), and the public checkpoint key.
- The first record of a new month file chains to the last line of the
  previous file. `verify` reads the files in name order.

#### 6.4.2 Checkpoints

The daemon writes `kind = "checkpoint"` after every
`[audit] checkpoint_every` records (default 1 000), every
`checkpoint_interval` (default 15 min) when there were new records, and at
stop. A checkpoint signs `head_seq` and `head` (the hash of record
`head_seq`) with Ed25519. The signed message is:

```
saiife-checkpoint-v1\n<chain id>\n<head_seq>\n<head hex>\n<ts>
```

Key rotation writes `kind = "key_rotate"` signed by the old key and naming
the new one. The chain alone cannot show that the newest records were cut
off. A forwarded checkpoint can, because the outside copy knows a later
`head_seq` than the local files have.

#### 6.4.3 `saiife audit verify`

Checks, and reports by sequence number and file:

1. Each line parses, `seq` goes up by one, and `prev` matches the hash of
   the line before (catches edits, deletions, insertions and reordering).
2. Each checkpoint signature is valid for the key in force at that point.
3. With `--external <file or dir>` (a forwarded copy), the local chain
   contains every checkpoint the external copy has (catches a cut-off tail
   and a rewritten history).
4. v1 files (records with `v = 1`) are listed as "not chained (v1)", not as
   failures.

Exit code 0 means intact, 1 means a break was found, 2 means it could not
read the log.

#### 6.4.4 Developer mode

Developer mode also writes v2 records with `seq` and `prev`, so the format
is the same everywhere. With no daemon, the hook process takes an exclusive
`flock` on `<audit dir>/.chain.lock`, reads the last line of the current
month file, and appends. There is no signing key in developer mode: a key in
the user's own home proves nothing. The chain there catches careless edits,
not deliberate ones (§10).

#### 6.4.5 Who can read the audit

- Auditors (group `saiife-audit`) read the files directly. `saiife audit`,
  `--report` and `verify` work as they do in v1.
- Other users run `saiife audit`, and the CLI asks the daemon
  (`audit.query`). The daemon returns only records with that user's uid,
  across guard, connector and approval kinds. The masked inputs of other
  users stay private.
- `saiife audit` also still shows the user's old v1 log from the home
  folder, labelled "v1, before locked mode, not tamper-evident".

### 6.5 Audit forwarding (v1 §9.3)

Off by default. When on, the daemon sends every record, in order and at
least once, to each target. Targets:

| `type` | Transport | Use |
|---|---|---|
| `syslog` | RFC 5424 to the local `/dev/log` / `/var/run/syslog`, or remote over TCP with TLS (RFC 5425) | rsyslog, journald, syslog-ng, most SIEMs |
| `file` | append JSONL to a path (for example an NFS or SMB share), one file per host and month | file shares, log agents such as Fluent Bit or Vector |
| `https` | POST batches of JSON (at most 500 records or 1 MiB), with an optional `Authorization` header taken from the vault; Splunk HEC compatible when `format = "splunk-hec"` | SIEM HTTP inputs |

- A cursor per target (`state/forward-<name>.cursor`, the last `seq` that was
  sent) means an outage leaves a backlog, not a gap. The backlog is capped by
  the log's retention.
- Changes in a target's state (`connected`, `failing`, `recovered`,
  `backlog_dropped`) are records (`kind = "forward"`), so a quiet SIEM is not
  mistaken for a quiet machine (principle 5). Individual batches are not
  recorded, to avoid a feedback loop.
- The payload is the exact JSONL line, so the SIEM can run `verify` on its
  copy. The `rfc5424-json` syslog format puts the line in the MSG part,
  unchanged.

### 6.6 Vault

- **Locked mode:** `vault.bin` is owned by the daemon user and encrypted with
  XChaCha20-Poly1305 under the vault key (§5.2). Each entry has `name`,
  `kind` (`token`, `basic`, `header`, `oauth2`, `aws`, `gcp_sa`,
  `azure_sp`), the secret fields, `created_by` (uid), `created`,
  `last_used`, `rotate_after` (optional), and `allowed_services`. A secret
  can only be used by services named in that list.
- **Personal broker mode (after v2.0):** each secret is one item in the OS keychain
  (macOS Keychain with an access list that names the saiife binary; Linux
  Secret Service). The docs say plainly that any process of the same user can
  read these on Linux, and on macOS after one click the user may give.
  Built (plan 16): one keychain item (`saiife`/`vault-key`) holds the 32-byte
  vault key, and the secrets stay in `vault.bin` sealed under it, not one item
  per secret. `saiife daemon --user` on macOS is refused until the plan 13
  daemon port; the macOS Keychain backend is built and compile-checked.
- `saiife secret add <name> --kind token [--service shopify]` reads the value
  from the terminal without echo, or from `--from-file <path>` /
  `--from-env <VAR>`. The value goes to the daemon over the socket (admin
  uids only in locked mode) and is never written to a record. Records keep
  `secret_add`, `secret_use` (once per request) and `secret_remove`, with the
  name only.
- `saiife secret import` finds plaintext credentials (§6.16 scan list),
  shows each one by path and name, and for each one the admin confirms:
  stores it, suggests a service entry, and removes or empties the source
  file. A backup copy goes to `/var/lib/saiife/state/import-backup/` (owned
  by the daemon user) for 7 days.
- OAuth2 refresh tokens are refreshed by the daemon. A failed refresh is a
  `secret`/`refresh_failed` record and a notification.

### 6.7 Connector gateway

#### 6.7.1 Request pipeline

For every request, from any entry point (`saiife api`, HTTP, MCP):

1. **Identify:** uid from peer credentials; agent session by attribution
   (§6.9.3); the project as reported by the client (attribution only).
2. **Lockdown:** if lockdown is on (proposed, §6.18), deny.
3. **Scope:** the uid's single `[[scope]]` (decision 6) must list the
   service. A uid with no scope, or whose scope does not list the service,
   is denied with `rule = "no_scope"`.
4. **Resolve the operation:** named operations directly; proxy paths by
   matching `method` and the path against the manifest's templates. No match
   means deny (`unknown_operation`). Paths are normalized first, and `..`,
   `%2e`, `%2f`, `//`, absolute URLs and a different host are rejected.
5. **Validate parameters** against the manifest types. Unknown parameters
   are rejected. Parameters fixed in the policy (`fixed = { shop = "acme" }`)
   cannot be overridden.
6. **Policy:** evaluate deny, then ask, then allow; nothing matched means
   deny (§6.9.1).
7. **Limits:** check the rate, count and amount limits (§6.9.2). Over a
   limit means deny with `limit = "<name>"`.
8. **Ask:** create an approval request and return pending (§6.10).
9. **Send:** build the upstream request from the manifest: base URL, auth
   from the vault, only the headers the manifest allows (agent-supplied
   `Authorization`, `Cookie` and `Host` are dropped). TLS with rustls and the
   system root store plus `/etc/saiife/ca`. Redirects are followed only to
   the same host, at most 3. Timeout 30 s by default.
10. **Mask the response:** replace every vault value in use (and its
    base64, URL-encoded and hex forms) and every v1 masking pattern
    (§6.3 in v1) with `[MASKED]`. Apply field redaction (proposed, §6.7.3).
    Cut at `max_response_bytes` (default 5 MiB) and say so.
11. **Record:** one `connector` record (§8.5) with masked parameters, body
    hash and size (never the body), status, response size and duration.
12. **Return** the result.

Steps 1–8 never touch the network. A denied request costs no upstream call.

#### 6.7.2 Agent-facing interface

```
saiife api --list [<service>]             # services and operations this user may call, with their policy action
saiife api <service> <operation> [k=v ...] [--body @file|-] [--wait <dur>] [--json]
saiife api result <request-id>            # result of a request that waited for approval
saiife api collection list|run <name> [k=v ...]
```

Exit codes: 0 done, 1 upstream error (status ≥ 400, shown), 2 denied,
3 pending approval (prints the id and how to get the result), 4 limit
reached, 5 saiife unavailable. Output is the upstream data as JSON on stdout,
and a one-line summary on stderr.

For example, `saiife api shopify orders.list status=open limit=50` prints the
orders as JSON.

#### 6.7.3 Response field redaction (proposed addition; in v2.0)

Kept in v2.0 by the designer's call under owner decision 1. It is one more
step in the response masking pass that plan 10 builds anyway: field paths
are matched on the parsed JSON before the value scan.

```toml
[services.shopify.redact]
fields = ["customer.email", "customer.phone", "*.billing_address"]
```

Why: for a DPO, an agent that only needs order totals should not receive
customer contact data. Data minimization (GDPR art. 5(1)(c)) as a policy
line, not a promise.

### 6.8 Connectors

#### 6.8.1 Manifest

Each connector is one TOML file in `crates/broker/connectors/`, embedded at
build time. The schema is in §8.4. A manifest declares: base URL template,
auth kinds it accepts, service parameters set by the admin (for example the
shop name), operations (id, capability, kind `read`/`write`/`delete`/`bulk`,
method, path template, query and body parameters with types, pagination
style, optional amount field), allowed request headers, and hosts.

Admins can add local manifests in `/etc/saiife/connectors/*.toml` (the same
schema, root-owned) for in-house APIs. A local manifest cannot use the id of
a built-in one.

#### 6.8.2 Generic HTTP connector

`connector = "http"`, with operations defined in the service config instead
of a manifest:

```toml
[services.erp]
connector = "http"
base_url = "https://erp.acme.internal/api"
secret = "erp-token"
auth = { kind = "header", name = "X-Api-Key" }

[[services.erp.operation]]
id = "invoices.list"
capability = "invoices:read"
method = "GET"
path = "/v2/invoices"
query = ["status", "from", "to"]
```

The same pipeline applies. This is also the "webhooks (outbound)" connector
from v1 §9.5: a `POST` operation to a fixed URL.

#### 6.8.3 Connector list (all v1 §9.5 v2 rows)

| Wave | Connectors | Plan |
|---|---|---|
| 1 (v2.0) | Shopify, HubSpot, GitHub, generic HTTP (includes outbound webhooks) | 10 |
| 2 | Stripe, Slack, Linear, Sentry, GitLab, PagerDuty, Discord | 14 |
| 3 | Salesforce (OAuth2), Intercom, Zendesk, Airtable, Segment, WooCommerce, Email (SMTP send; IMAP read) | 14 |
| Cloud | AWS, GCP, Azure (§6.13) | 15 |

Wave 1 is unchanged by review (owner decision 4). Its manifests include the
write operations, not only reads: for example Shopify `products.update`,
`refunds.create` and `discounts.create`, HubSpot `contacts.update` and
`deals.update`, GitHub `issues.create` and `pulls.create`. Like every
operation, writes are denied until the policy allows them, and an admin can
put them under `ask` and amount caps (§6.9.4). The suggested policy on each
docs page puts every write under `ask`.

Each connector ships with a docs page (operations, capabilities, a
suggested read-only policy) and an offline test suite against a mock server
built from the vendor's documented responses.

`saiife connect <service>` (admin) picks the connector, runs `secret add`
(or an OAuth2 device or paste flow), and writes
`/etc/saiife/policy.d/<service>.toml` with every operation listed and
commented out. The service starts with everything denied.

Built (plan 14):

- OAuth2 uses a paste flow only: `secret add --kind oauth2` (and `connect`)
  takes `client_id`, `client_secret` and `refresh_token`. There is no device
  flow in this version.
- The Sentry token mask shape is `sntry[su]_` (the real prefixes are
  `sntrys_` and `sntryu_`).
- `policy check` accepts a concrete qualifier rule such as
  `messages:read:channel=C0123` for an operation whose qualifier is a
  template (`channel={channel}`): a `{placeholder}` counts as a wildcard when
  the rule is matched against the operation.

### 6.9 Policy engine and limits

#### 6.9.1 Capabilities and rules

- A capability is `resource:verb[:qualifier]`. Verbs are `read`, `write`,
  `delete`, `export`, `admin`. `*` matches one segment. The qualifier scopes
  to a resource: an ARN glob, `repo=acme/*`, a Slack channel.
- The simple form is three lists per service: `allow`, `ask`, `deny`.
- The table form adds conditions on parameters:

  ```toml
  [[services.github.rule]]
  capability = "issues:write"
  when = { repo = "acme/*" }
  action = "allow"
  ```

- Order: any matching `deny` wins, then `ask`, then `allow`. Nothing matching
  means deny. This is the same order as v1 §9.2.
- The project file (`.saiife/config.toml`) may add `deny` and `ask` entries
  for a service and never `allow` (in locked mode). In developer and personal
  broker modes it may add `allow` too.

#### 6.9.2 Limits (v1 §9.2 "rate and blast-radius limits")

```toml
[services.shopify.limits]
requests_per_minute = 60
writes_per_hour = 50          # kind = write
deletes_per_day = 0           # kind = delete (0 = never, even if allowed)
bulk_per_session = 1          # kind = bulk
max_response_bytes = 5_242_880
amount_per_day = { max = 500, currency = "EUR" }   # proposed addition, §6.9.4
```

- Each limit is counted per (uid, service) and, where a session is known,
  also per (uid, service, session). Both must be under the limit.
- Sliding windows, in memory, rebuilt from connector records at start, so a
  daemon restart does not reset them.
- Hitting a limit is a `deny` record with `limit` set, and a notification
  (proposed, §6.10.3) the first time per window.

#### 6.9.3 Sessions (attribution, not authorization)

The daemon links a request to an agent session without trusting the client:

1. On each hook record, the daemon walks up the process tree from the hook's
   peer pid (`/proc/<pid>/stat` on Linux, `KERN_PROC_PID` on macOS, both
   readable for other users' processes) to the nearest process whose name is
   a known agent (`claude`, `codex`, `gemini`, or `node` with one of those in
   its command line). It stores (that pid, its start time) → the hook's
   `session_id`.
2. On each connector request, it walks up from the requester's pid the same
   way and looks up the session.
3. No match means `session = null`. Only per-uid limits apply, and those are
   always enforced. A double-fork to escape the session therefore lands in
   the stricter shared bucket, not in a fresh one.

The process name can be faked by the same user, which is why sessions are
used only for attribution and finer limits. v3 replaces this with a session
identity issued by the runner.

#### 6.9.4 Amount caps (proposed addition; in v2.0, owner decision 1)

Manifests mark operations that move money with `amount = { field =
"amount", currency_field = "currency", unit = "minor" }` (Stripe refunds,
Shopify refunds, discounts). `amount_per_day` and `amount_per_request` cap
them.

Why: an unattended support agent that may issue refunds needs a ceiling
that does not depend on the agent's judgment.

### 6.10 Approvals

#### 6.10.1 Flow

1. An `ask` rule matches. The daemon stores the request with exactly the
   resolved operation and parameters (§8.10), writes an `approval`/`created`
   record, notifies (if set up), and returns `pending` with an id, for
   example `#42`.
2. The agent gets exit code 3 (`saiife api`), HTTP 202, or an MCP result
   saying "waiting for approval #42". `--wait 10m` blocks the CLI until a
   decision or the timeout.
3. An approver runs `saiife approvals` to list requests,
   `saiife approvals show 42` to see the full masked request, and
   `saiife approve 42 [--note "…"]` or `saiife reject 42`.
4. On approval, the **daemon** sends the stored request (the agent cannot
   change it after approval). The result is kept for 24 h for
   `saiife api result 42`.
5. Requests expire after `[approval] timeout` (default 30 min) and become
   `expired`. Every step is a record linked by `approval` id.

#### 6.10.2 Who can approve

- The approver's uid must match `[approval] approvers` and must not be the
  uid that created the request.
- On a dedicated agent account this is natural: the human logs in as
  themself (locally or over SSH) and approves.
- On a developer's own machine the requester and the human share a uid.
  Re-authentication ships in v2.0 (owner decision 3). `same_user = "reauth"`
  allows the same uid if it proves a human is present:
  - Linux (v2.0): the daemon runs `pkcheck --action-id com.saiife.approve
    --process <pid>,<start>,<uid> --allow-user-interaction`. `system install`
    writes the action file
    `/usr/share/polkit-1/actions/com.saiife.approve.policy` with
    `allow_any`, `allow_inactive` and `allow_active` all set to `auth_self`
    (never `auth_self_keep`), so the polkit agent asks for the user's
    password every time. An agent process cannot answer that prompt without
    the password. In a session with no polkit agent (for example SSH), the
    CLI starts `pkttyagent` on the approver's terminal.
  - macOS (v2.1): the CLI gets the authorization right `com.saiife.approve`
    (rule `authenticate-session-owner`, `timeout = 0`, so Touch ID or the
    password each time) and passes the external form to the daemon, which
    checks it. (The v2.1 plan confirms the daemon user can verify a client's
    authorization.)
- **Fallback without polkit** (owner decision 3). When `pkcheck` or the
  polkit daemon is missing (common on minimal servers), `same_user =
  "reauth"` behaves as `same_user = "deny"`: only a second uid in
  `approvers` can approve. A same-uid `saiife approve` is refused with that
  reason and recorded. `doctor` reports "re-authentication unavailable:
  approvals need a second account" as a warning, and `system install` prints
  it too.
- `same_user = "deny"` (the strict choice) can still be set by an admin who
  wants approvals from a second account only. `system install` writes
  `"reauth"` when polkit is present and `"deny"` otherwise.
- Personal broker mode (after v2.0) allows any approval from the same user.
  The docs say this is a workflow aid, not a control.

#### 6.10.3 Notifications (proposed addition; in v2.0, owner decision 1)

```toml
[notify]
on = ["approval_created", "limit_reached", "error_denied_burst", "chain_break", "forward_failing", "lockdown"]
[notify.targets.ops]
type = "webhook"        # webhook | smtp | command
url = "https://hooks.slack.com/services/…"   # stored as a secret reference in practice: url_secret = "slack-hook"
```

- Outbound only. A notification carries the request id, the service and
  operation, the uid and host, and a masked one-line summary. It never
  carries secrets or bodies, and never a link that approves anything: the
  approval happens on the machine.
- `command` runs a local program as the daemon user, for example `logger` or
  a site-specific pager script.
- Sent notifications are records (`kind = "notify"`).

Why: with nobody watching, an `ask` rule without a notification turns into a
silent stall, and limit hits or chain breaks go unseen until someone reads
the log.

#### 6.10.4 Approval for commands (proposed addition; in v2.0, owner decision 1)

Admins can turn chosen guard rules from `deny` into `ask`:

```toml
[guard]
ask = ["core.git/force-push", "db.postgres/drop-database", "container.k8s/delete-namespace"]
```

When such a rule matches, `check` asks the daemon `grant.consume` for a grant
keyed by SHA-256(uid, agent, project, tool, exact input). If one exists, it
is used up, the call is allowed, and the record says `approved` with the
approval id. If not, the daemon creates a request and the hook denies with:
"Needs approval: request #42. Run the same command again after it is
approved." Grants last 15 minutes and are good for one use.

Why: without it, an unattended agent that hits a rule like a force-push
either gives up or looks for a way around it. With it, a human can say yes
once to the exact command, and nothing waits inside a hook.

### 6.11 Environments (v1 §9.5; after v2.0, plan 14)

```toml
[environments.staging]
services.shopify.secret = "shopify-staging"
services.shopify.params = { shop = "acme-staging" }

[environments.prod]
guard.packs = ["iac.terraform", "db.postgres"]      # added to the base list
services.shopify.ask = ["products:write"]
```

- An environment adds packs and overrides service settings (secret,
  parameters, rule lists, limits) on top of the base config. It cannot turn
  off a default-on pack.
- Locked mode: an environment is bound to a scope by the admin
  (`[[scope]] env = "prod"`). Since each uid has exactly one scope
  (decision 6), each uid has exactly one environment. The project path never
  chooses it. `saiife env use <name> --scope <scope>` needs admin rights and
  rewrites that binding. The current environment is part of the
  effective-policy hash, so every record shows which environment was in
  force.
- Developer and personal broker modes: `saiife env use <name>` writes
  `env = "<name>"` into `.saiife/config.toml`.
- `saiife env list` shows the environments and which one applies here.

Built (plan 14):

- An environment may widen policy as well as narrow it: its `allow`, `ask`,
  `deny` and `rule` lists replace the base lists, and `params`, `fixed` and
  `limits` merge key by key.
- `[environments]` may appear only in `config.toml`, not in `policy.d` or a
  project file.
- Environment names match `[a-z0-9_-]{1,64}`.
- A malformed `env` value is a bad request in locked mode too; it never falls
  back to another environment.
- `env use --scope` is root only (the spec's "admin rights").
- In developer and personal-broker mode an environment changes connector
  calls only; its guard packs apply in locked mode. A developer-mode `policy
  show` prints a line saying it does not reflect the project env.

### 6.12 Collections (v1 §9.5 "agent-facing API client + collections"; after v2.0, plan 14)

Saved requests in the project, `.saiife/collections/<name>.toml`:

```toml
name = "open-orders-report"
[[step]]
service = "shopify"
operation = "orders.list"
params = { status = "open", limit = "250" }
```

Collections may be written by the agent: each step still goes through the
full pipeline, so a collection cannot do more than its steps could one by
one. `saiife api collection run <name> [k=v …]` fills `{{var}}` placeholders.
They are named requests, not a flow engine (flows are v3).

### 6.13 Cloud credentials (v1 §9.5 "per-session cloud credentials"; after v2.0, plan 15)

Two modes per cloud service:

- `mode = "sign"` (default): the daemon signs each request itself (AWS
  SigV4; GCP and Azure OAuth2 access tokens from a service account or
  service principal held in the vault). The agent calls `saiife api aws
  s3.get_object bucket=… key=…` or the proxy path. The agent never sees
  credentials. Capabilities follow the IAM action (`s3:GetObject` maps to
  `s3:read:<arn>`).
- `mode = "sts"` (opt-in, labelled): `saiife run --cloud aws --
  <command>` mints credentials that last at most 15 minutes with
  `sts:AssumeRole` and an inline session policy built from the saiife allow
  list, and puts them only in that command's environment. This hands a
  credential to agent-controlled code. It is scoped and short-lived, but an
  agent can copy it. `doctor` lists every service in STS mode. It exists
  because many existing tools (terraform, the aws CLI) cannot work through a
  signing proxy.

GCP and Azure STS equivalents (short-lived access tokens for an
impersonated service account; Azure workload identity) follow the same rule.

### 6.14 `saiife run --secret`

`saiife run --secret <name>[:ENV_VAR] -- <cmd>` puts a secret into one
command's environment and masks it in that command's output (v1 §9.2).

The command runs as the agent's user, so the agent's code holds the secret
for that moment (`sh -c 'echo $X | base64'` defeats output masking). In
locked mode it is therefore **off unless the secret allows it**:

```toml
[secrets.db-readonly]
run_allow = ["/usr/bin/psql", "/usr/bin/pg_dump"]   # resolved, root-owned executables only
```

`<cmd>` must resolve to a listed, root-owned executable, and no shell or
interpreter may be listed (the config check refuses `sh`, `bash`, `python`,
`node` and similar). The daemon passes the value to the client over the
socket. The client execs the command with the variable set. Each use is a
record. The docs recommend a connector instead wherever one exists.

### 6.15 MCP (proposed additions, after v2.0)

Both parts ship after v2.0 (owner decision 1). Until then, locked mode
allows only the unbrokered MCP servers an admin lists, with warnings
(§6.1.4).

**`saiife mcp`: connectors as MCP tools.** A stdio MCP server that the agent
config starts (`saiife mcp`). It lists each allowed operation as a tool
(`shopify_orders_list`) with a JSON schema generated from the manifest, and
forwards calls to the daemon (same pipeline).
Why: agents call MCP tools more reliably than they compose CLI lines, and
schemas cut malformed requests.

**MCP gateway: third-party MCP servers run by the daemon.** The admin
declares MCP servers in `/etc/saiife/policy.d/mcp-<name>.toml` (command,
arguments, secrets to pass in its environment). The daemon starts them as the
daemon user, and `saiife mcp` also lists their tools, prefixed by server
(`linear__create_issue`), under per-tool `allow`, `ask` and `deny` lists.
Why: MCP servers configured by users keep their tokens in the user's config
files, which is exactly the credential leak v2 closes elsewhere.

### 6.16 `saiife doctor` (proposed addition; in v2.0, owner decision 1)

Checks the host preconditions of §5.6, the files and fingerprints in
`installed.toml`, the daemon's health, the chain head and the last
checkpoint, forwarding state, and per agent the managed hook and version.
Also a **plaintext-secret scan** of each agent user's reach: `.env*` files
under the scoped project paths, `~/.aws/credentials`, `~/.config/gcloud`,
`~/.azure`, `~/.kube/config`, `~/.docker/config.json`, `~/.npmrc`,
`~/.pypirc`, `~/.netrc`, `~/.git-credentials`, `~/.config/gh/hosts.yml`,
`~/.vault-token`, and tokens inside agent MCP configs. Each finding names
the path, never the value. Run as root it checks every scoped user; run as a
user it checks that user.

Further checks that come from the review decisions (§0):

- The lock label of each agent, from the plan 7 gate: "locked", "locked
  with caveats" or "not lockable" (decision 9).
- Re-authentication: whether `pkcheck` and the polkit daemon are present and
  the `com.saiife.approve` action is installed. If not, a warning:
  "re-authentication unavailable: approvals need a second account"
  (decision 3).
- One warning per MCP server in `[guard.mcp] allow_servers`: it bypasses the
  broker (decision 10).
- How the vault key is held: an encrypted systemd credential (TPM or host
  key) or a plain key file (systemd < 250), and whether `SO_PEERPIDFD` is
  available (decision 8).
- The system is a supported one for locked mode (Ubuntu 22.04+, Debian 12+,
  RHEL 9+, systemd). On anything else, a failure: developer mode only.
- The scopes do not overlap for any current user or group member
  (decision 6).
- The agent's model login is reported as information, not a failure: "the
  agent holds its own model-provider login (not brokered in v2)", or "local
  model" when the agent's config points to a local endpoint (decision 5).

`--json` gives machine-readable output, and the exit code is 0 (all pass),
1 (a warning), or 2 (a failure). Fleet tools can run it on a schedule.

Why: the lock holds only when the host preconditions hold, and "never sees
credentials" holds only once the credentials are gone from the agent's
reach. `status` checks hooks. `doctor` checks the machine.

### 6.17 `core.lock` pack (proposed addition; in v2.0, owner decision 1)

On by default in locked mode, and opt-in elsewhere. It denies:

- privilege changes: `sudo`, `su`, `doas`, `pkexec`, `run0`, and `osascript`
  with `with administrator privileges`;
- touching saiife's service: `systemctl … saiifed`, `launchctl … com.saiife.*`,
  `kill`/`pkill` of `saiifed`;
- persistence that runs code later outside any agent session: `crontab`,
  `at`, `systemd-run --user`, `launchctl load|bootstrap` of a user agent, and
  writes to `~/.config/systemd/user/`, `~/Library/LaunchAgents/`,
  `~/.config/autostart/`;
- turning off agent safety switches on the command line:
  `--dangerously-bypass-hook-trust`, `GEMINI_CLI_SYSTEM_SETTINGS_PATH=` and
  `GEMINI_CLI_SYSTEM_DEFAULTS_PATH=`.

Why: most of these would fail on permissions anyway, but a clear denial
stops a helpful agent from looping on them, and the persistence rules close
the cheapest way to run code later with no hook around it.

### 6.18 Lockdown (proposed addition; in v2.0, owner decision 1)

`saiife lockdown on [--scope all|connectors] [--reason "…"]` and `saiife
lockdown off`, for admins and approvers. `connectors` denies every connector
request at once. `all` also makes every hook deny (the agents stop working).
The flag survives daemon restarts, is a record, and triggers a notification.
Why: when an unattended agent misbehaves, the person on call needs one
command that stops it without finding and killing processes.

### 6.19 Report

`saiife audit --report` keeps the v1 sections and adds, without network
resources as before:

- Chain status: verified or broken (with where), and the last checkpoint.
- Connector activity per service: requests, denies, limits hit, approvals.
- Approvals: who decided what, and how long it took.
- `error_denied` events, daemon restarts, forwarding outages.
- The policy in force for each period, from `policy` records (closes the
  plan 4 carry-over).
- Mode per host: developer, personal broker or locked.

### 6.20 Egress recipe for dedicated agent accounts (proposed addition, docs only; in v2.0)

Kept in v2.0 by the designer's call under owner decision 1: it is one docs
page plus one `doctor` check in plan 12.

A documented, tested `nftables` rule set (Linux) that drops outbound traffic
for the agent account's uid (`meta skuid agent-shop`), except to the model
provider or local model server and DNS. All brokered traffic leaves as the
daemon user, so connectors keep working. No code, only a docs page and a
`doctor` hint when the rule set is missing.

Why: it removes most of the exfiltration gap in §10 for the recommended
unattended setup, years before v3's egress control, at the cost of one page.
(macOS has no per-uid firewall in `pf` that we can rely on. The page says so.)

## 7. Commands

New and changed commands. v1 commands not listed are unchanged. Not in
v2.0: `saiife daemon --user`, the personal-broker side of `secret` and
`connect` (decision 7), `saiife mcp` (decision 1), `saiife env` and
`saiife api collection` (plan 14), `saiife run --cloud` (plan 15).

| Command | Who | Behavior |
|---|---|---|
| `saiife system install [--config <file>] [--agents claude,codex,gemini] [--approvers <list>] [--non-interactive]` | root | Create users and groups, install the binary to `/opt/saiife/bin`, write `/etc/saiife` (from `--config` or a commented default), the unit or plist, and the managed hooks for the chosen agents; start the daemon; write `installed.toml`; run `doctor`. Idempotent. |
| `saiife system uninstall [--keep-audit]` | root | Remove exactly what `installed.toml` lists. The audit and vault are kept unless `--purge`. |
| `saiife daemon --system \| --user` | service manager | Run the daemon. `--user` is personal broker mode (`$XDG_RUNTIME_DIR/saiife/`), after v2.0. Built (plan 16): Linux only; macOS is refused until the plan 13 daemon port. |
| `saiife doctor [--user <name>] [--json]` | anyone (more checks as root) | §6.16 (proposed; in v2.0). |
| `saiife status` | anyone | v1 checks, plus mode, daemon health, chain head, pending approvals for this user, lockdown state, each agent's lock label (decision 9), and one warning per unbrokered MCP server allowed in policy (decision 10). |
| `saiife check --managed …` | managed hooks | §6.1.2. |
| `saiife init` | user | In locked mode: writes the project config, adds packs only, writes no hooks for agents that have managed hooks. |
| `saiife init --off` | user / admin | In locked mode: removes leftover project hooks only. It cannot touch managed hooks (those need `system uninstall`). |
| `saiife secret add\|list\|remove\|rotate\|import` | admin (locked) / user (personal broker) | §6.6. `list` shows names and metadata, never values. Built (plan 16): `import` is refused in personal broker mode (`personal broker: use secret add`). |
| `saiife connect <service>` | admin / user | §6.8.3. |
| `saiife api …` | agent user | §6.7.2. |
| `saiife api token` | agent user | Bearer token for the optional TCP listener. |
| `saiife run --secret <name> -- <cmd>` | agent user | §6.14. |
| `saiife run --cloud <service> -- <cmd>` | agent user | STS mode only, §6.13. |
| `saiife approvals [list\|show <id>]` | approvers; requesters see their own | §6.10. |
| `saiife approve <id> [--note]` / `saiife reject <id> [--note]` | approver | §6.10.2. |
| `saiife env list\|use <name>` | user (developer) / admin (locked) | §6.11. |
| `saiife policy show [--effective] [--user <u>]` | anyone (own scope); admin (any) | Print the merged policy and its hash. |
| `saiife policy check <file>` | anyone | Validate a config file without loading it, including overlapping scopes (decision 6) (proposed, with `test`; in v2.0). |
| `saiife policy test <file>` | anyone | Run `[[example]]` cases (§8.1) against a policy: "this request → allow/ask/deny", "this command → deny". Exit 1 on any mismatch (proposed addition: policies in git need a CI check, like `saiife-examples` blocks for packs). |
| `saiife policy reload` | admin | Same as SIGHUP. |
| `saiife audit verify [--external <path>]` | auditor / admin; developer mode: the user | §6.4.3. |
| `saiife audit [filters]` | anyone | Through the daemon for non-auditors (§6.4.5). New filters: `--kind connector\|approval\|guard`, `--service <s>`. |
| `saiife lockdown on\|off` | admin / approver | §6.18 (proposed; in v2.0). |
| `saiife mcp` | agent config | §6.15 (proposed; after v2.0). |

## 8. Config and data formats

### 8.1 `/etc/saiife/config.toml`

```toml
version = 2
locked = true                    # v1 reserved this key (v1 §5.1); true = locked mode

[daemon]
user = "saiife"                  # "_saiife" on macOS
socket_dir = "/run/saiife"       # "/var/run/saiife" on macOS; fixed in locked mode

[admin]
groups = []                      # uids in these groups get admin ops besides root

[guard]
packs = ["db.postgres"]          # added to the default-on packs (core.filesystem, core.git,
                                 # core.secrets, core.self, and core.lock when locked)
ask = ["core.git/force-push"]    # proposed (§6.10.4)
budget_ms = 50
fail = "closed"                  # forced "closed" when locked = true; "open" | "closed" otherwise

[guard.mcp]
allow_servers = []               # MCP servers allowed in locked mode, unbrokered (§6.1.4)

[audit]
dir = "/var/log/saiife/audit"
retention_months = 24            # older month files are deleted by the daemon, with a record
checkpoint_every = 1000
checkpoint_interval = "15m"
min_free_mb = 512
fsync = "checkpoint"             # "always" | "checkpoint" (fdatasync at checkpoints and every 1 s)

[audit.forward.siem]
type = "syslog"
address = "tls://siem.acme.internal:6514"
ca = "/etc/saiife/ca/acme.pem"
format = "rfc5424-json"

[approval]
approvers = ["group:saiife-approvers"]
same_user = "deny"               # "deny" | "reauth"
timeout = "30m"
grant_ttl = "15m"                # command grants (§6.10.4)

[notify]                         # proposed (§6.10.3)
on = ["approval_created", "limit_reached", "chain_break", "forward_failing", "lockdown"]
[notify.targets.ops]
type = "webhook"
url_secret = "slack-ops-hook"

[gateway]
tcp = ""                         # "127.0.0.1:7431" to enable; off by default
max_response_bytes = 5242880
upstream_timeout = "30s"

[[scope]]
name = "shop-agent"
users = ["agent-shop"]           # OS users or "group:<name>"
projects = ["/srv/agents/shop/**"]   # attribution only (client-reported); never selects scope or env
services = ["shopify", "hubspot"]
env = "prod"
# Builder's call 6: each uid matches at most one scope. A user listed in two
# scopes, directly or through a group, is a config error: `policy check`
# fails and the daemon refuses to load the policy (it keeps the last good one,
# or starts with connectors denied).

[[example]]                      # used by `saiife policy test` (proposed)
user = "agent-shop"
request = "shopify orders.list status=open"
expect = "allow"
[[example]]
user = "agent-shop"
request = "shopify customers.export"
expect = "deny"
```

`/etc/saiife/policy.d/shopify.toml`:

```toml
[services.shopify]
connector = "shopify"
secret = "shopify-prod"
params = { shop = "acme" }
allow = ["orders:read", "products:read"]
ask   = ["products:write", "refunds:write"]
deny  = ["customers:export", "*:delete"]

[services.shopify.limits]
requests_per_minute = 60
writes_per_hour = 50
bulk_per_session = 1
amount_per_day = { max = 500, currency = "EUR" }     # proposed

[services.shopify.redact]                            # proposed
fields = ["customer.email", "customer.phone"]
```

**Merging.** `config.toml` first, then `policy.d/*.toml` in name order.
Arrays under `[guard]` are joined. A service may be defined in one file only:
a second definition is a config error. The daemon then refuses the new
policy and keeps the old one (or starts with connectors denied). Unknown keys
are errors, to catch typos in a security config. Overlapping scopes are an
error at load time. Because group membership can change after a load, the
daemon also checks each request: a uid that matches two scopes at that
moment is denied with `rule = "scope_conflict"`, and the denial is recorded
(fail closed). The effective policy (merged
config, environment, active packs and their versions) is written as
canonical JSON with sorted keys, and its SHA-256 is the `policy` hash.

### 8.2 Project config `.saiife/config.toml`, version 2

```toml
version = 2
packs = ["core.filesystem", "core.git", "core.secrets", "db.postgres"]
env = "staging"                 # developer mode only; ignored when locked
locked = false                  # ignored at project level from v2 on: only /etc decides

[services.shopify]
deny = ["products:write"]       # projects may narrow; "allow" only outside locked mode
```

In locked mode the project config is merged **add-only**: extra packs, extra
`deny` and `ask` entries. It can never remove a pack, add an `allow`, change
a secret, or change the environment. A v1 file (`version = 1`) stays valid.

### 8.3 Managed agent configs

**Claude Code** `/etc/claude-code/managed-settings.d/50-saiife.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "*",
        "hooks": [ { "type": "command",
                     "command": "/opt/saiife/bin/saiife check --managed --hook-exit --agent claude",
                     "timeout": 10, "onFailure": "block" } ] }
    ],
    "ConfigChange": [
      { "hooks": [ { "type": "command",
                     "command": "/opt/saiife/bin/saiife check --managed --hook-exit --agent claude --event config-change",
                     "timeout": 10, "onFailure": "block" } ] }
    ]
  },
  "disableAllHooks": false
}
```

`allowManagedHooksOnly` is not set by saiife: it would switch off the
company's and users' other hooks. `system install --managed-hooks-only` sets
it when the admin asks.

**Codex** `requirements.toml` (managed dir verified in plan 7):

```toml
[features]
hooks = true

[[hooks.PreToolUse]]
matcher = ".*"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/opt/saiife/bin/saiife check --managed --hook-exit --agent codex"
timeout = 10
statusMessage = "saiife guard (locked)"
```

When the file already exists, saiife edits it with `toml_edit` and tags its
entry, as v1 does for project files. `installed.toml` stores the fingerprint
of saiife's entry, not of the whole file.

**Gemini CLI** system `settings.json`:

```json
{ "hooks": { "BeforeTool": [ { "hooks": [ { "type": "command",
    "command": "/opt/saiife/bin/saiife check --managed --hook-exit --agent gemini",
    "name": "saiife", "timeout": 10000 } ] } ] } }
```

(The matcher is left out, which means all tools. The hooks on/off key is
added once plan 7 finds it.)

### 8.4 Connector manifest

`crates/broker/connectors/shopify.toml`:

```toml
id = "shopify"
version = 1
title = "Shopify Admin API"
base_url = "https://{shop}.myshopify.com/admin/api/2026-07"
hosts = ["*.myshopify.com"]
auth = [{ kind = "header", name = "X-Shopify-Access-Token", secret_field = "token" }]
request_headers = ["Content-Type", "Accept", "Idempotency-Key"]

[params.shop]                    # set by the admin in the service config, never by the agent
type = "string"
pattern = "^[a-z0-9-]+$"
required = true

[[operation]]
id = "orders.list"
capability = "orders:read"
kind = "read"
method = "GET"
path = "/orders.json"
query = { status = "enum:open,closed,cancelled,any", limit = "int:1..250", since_id = "int", created_at_min = "datetime" }
pagination = "link-header"

[[operation]]
id = "refunds.create"
capability = "refunds:write"
kind = "write"
method = "POST"
path = "/orders/{order_id}/refunds.json"
path_params = { order_id = "int" }
body = "json"
amount = { field = "refund.transactions[].amount", currency_field = "refund.currency", unit = "major" }
```

The schema is versioned (`version`). Unknown keys are build errors (a test
loads every manifest). Path parameters are percent-encoded and may not hold
`/`.

### 8.5 Audit record v2

Common fields (all kinds):

| Field | Type | Notes |
|---|---|---|
| `v` | int | `2` |
| `seq` | int | chain position |
| `prev` | hex | SHA-256 of the previous line's bytes |
| `ts` | string | UTC, ms, as v1 |
| `kind` | string | `guard`, `connector`, `approval`, `secret`, `policy`, `daemon`, `forward`, `notify`, `lockdown`, `checkpoint`, `key_rotate`, `genesis` |
| `host` | hex | host id (§6.4.1) |
| `uid`, `user` | int, string | from peer credentials (daemon-written) or the process (developer mode) |
| `mode` | string | `developer`, `personal`, `locked` |
| `policy` | string | `sha256:<hex>` of the effective policy |
| `agent`, `project`, `tool`, `input`, `decision`, `saiife` | as v1 | **always present** so 0.1.0 readers can show every record; for non-guard kinds `tool` is the kind and `input` is a short masked summary |
| `session`, `pack`, `rule`, `reason` | as v1 | optional |
| `peer` | object | `{ "pid": 4242, "comm": "saiife" }`, attribution only |
| `permission_mode` | string | optional, the agent's permission mode from the hook payload (shows unattended runs) |

`decision` values: v1's `allow`, `deny`, `error_allowed`, plus `error_denied`,
`ask`, `approved`, `rejected`, `expired`. 0.1.0 readers keep unknown values
(`DecisionKind::Unknown`).

Guard record:

```json
{"v":2,"seq":1042,"prev":"9f2c…","ts":"2026-11-02T08:14:02.381Z","kind":"guard","host":"5ab1…",
 "uid":1001,"user":"agent-shop","mode":"locked","policy":"sha256:77e0…",
 "agent":"claude","project":"/srv/agents/shop","session":"…","tool":"Bash",
 "input":"git push --force origin main","decision":"ask","pack":"core.git","rule":"force-push",
 "reason":"needs approval: request #42","approval":42,"peer":{"pid":4242,"comm":"saiife"},
 "permission_mode":"bypassPermissions","saiife":"0.2.0"}
```

Connector record:

```json
{"v":2,"seq":1043,"prev":"c01d…","ts":"…","kind":"connector","host":"5ab1…","uid":1001,"user":"agent-shop",
 "mode":"locked","policy":"sha256:77e0…","agent":"claude","project":"/srv/agents/shop","session":"…",
 "tool":"api","input":"shopify orders.list status=open limit=50","decision":"allow",
 "service":"shopify","operation":"orders.list","capability":"orders:read","env":"prod",
 "params":{"status":"open","limit":"50"},"body_sha256":null,"body_bytes":0,
 "status":200,"resp_bytes":48211,"duration_ms":412,"secret":"shopify-prod","limit":null,
 "via":"cli","saiife":"0.2.0"}
```

`via` is `cli`, `http`, `mcp` or `approval` (sent by the daemon after
approval). Every string field written from agent input is masked as in v1,
including `params`. Bodies are never stored.

Other kinds carry their own fields (`approval`: `id`, `action`, `by_uid`,
`note`; `policy`: `result`, `files` with hashes, `diff_summary`; `daemon`:
`event`, `previous_clean_stop`; `checkpoint`: `head_seq`, `head`, `key`,
`sig`; `genesis`: `chain`, `key`). Readers must accept unknown kinds and
fields.

### 8.6 Checkpoint and genesis

```json
{"v":2,"seq":0,"prev":"0000…0000","ts":"…","kind":"genesis","chain":"6f1e…uuid","host":"5ab1…",
 "key":"ed25519:MCowBQYDK2VwAyEA…","agent":"","project":"","tool":"genesis","input":"","decision":"allow","saiife":"0.2.0"}
{"v":2,"seq":2001,"prev":"…","ts":"2026-11-02T08:30:00.000Z","kind":"checkpoint","head_seq":2000,
 "head":"a3b4…","key":"ed25519:<fingerprint>","sig":"<base64 64 bytes>", "agent":"","project":"","tool":"checkpoint","input":"","decision":"allow","saiife":"0.2.0"}
```

### 8.7 IPC frames (control socket)

```
frame   = u32 big-endian length || UTF-8 JSON (≤ 1 MiB)
request = {"id": <u64>, "op": "<name>", ...args}
answer  = {"id": <u64>, "ok": true, ...} | {"id": <u64>, "ok": false, "error": "<code>", "message": "..."}
```

| op | Caller | Args → answer |
|---|---|---|
| `hello` | any | `proto: 1, client: "0.2.0"` → `proto, daemon, mode` |
| `audit.append` | any uid (guard records) | `rec` (Record v2 without `seq`/`prev`/`uid`/`user`/`host`, which the daemon sets) → `seq` |
| `audit.query` | any (own uid) / auditor (all) | filters → `records[]`, `more` |
| `audit.verify` | auditor / admin | → report |
| `api.call` | scoped uid | `service, operation, params, body_b64?, wait_ms?, session_hint?` → `result` \| `pending: id` |
| `api.result` | requester | `id` → `result` \| `pending` \| `expired` |
| `api.list` | any | → services and operations for this uid |
| `grant.consume` | any (guard) | `key` → `granted: bool, approval?` |
| `approval.create` | any (guard) | `rec` (the ask record) → `id` |
| `approval.list` / `approval.show` | approver (all) / requester (own) | → items |
| `approval.decide` | approver | `id, action: approve\|reject, note?, auth?` (external auth form for reauth) → ok |
| `secret.add` / `secret.remove` / `secret.rotate` | admin | `name, kind, fields, allowed_services` → ok |
| `secret.list` | admin | → metadata |
| `secret.lease` | scoped uid | `name, exe` (§6.14) → `value` (only if `run_allow` matches) |
| `policy.show` / `policy.reload` | any (own) / admin | → effective policy, hash / result |
| `lockdown.set` | admin / approver | `scope, on, reason` → ok |
| `status` | any | → health, chain head, last checkpoint, forwarding, lockdown |

`audit.append` from a uid is accepted only for `kind = "guard"`. The daemon
overwrites any identity fields the client sent.

### 8.8 HTTP gateway (gateway socket)

| Method and path | Meaning |
|---|---|
| `GET /v1/services` | services and operations for the caller |
| `POST /v1/api/{service}/{operation}` | body `{"params": {...}, "body": {...}, "wait": "10m"}` |
| `ANY /v1/proxy/{service}/{upstream path}` | raw passthrough, matched to an operation by method and path (§6.7.1 step 4) |
| `GET /v1/requests/{id}` | result of an approved request |

Status codes: 200 done (upstream status in `X-Saiife-Upstream-Status` for
`/v1/api`, passed through for `/v1/proxy`), 202 pending (`{"pending": 42}`),
403 denied (`{"error": "denied", "rule": "..."}`), 429 limit, 502 upstream
failure, 503 lockdown or daemon not ready.

Example:

```
curl --unix-socket /run/saiife/gateway.sock \
  http://saiife/v1/proxy/shopify/orders.json?status=open
```

### 8.9 Vault file

```
vault.bin = magic "SAIIFEV1" || u8 version || 24-byte nonce || XChaCha20-Poly1305(key, nonce, aad = magic||version, plaintext = JSON)
JSON      = {"entries": [{"name": "...", "kind": "token", "fields": {"token": "..."}, "allowed_services": ["shopify"],
                          "created_by": 0, "created": "...", "last_used": "...", "rotate_after": null}]}
```

Written to a temp file, `fsync`ed, then renamed. A new nonce on every write.

### 8.10 Approval request file

```json
{"id":42,"created":"…","expires":"…","uid":1001,"user":"agent-shop","session":"…","agent":"claude",
 "type":"connector","service":"shopify","operation":"products.update","capability":"products:write",
 "params":{…masked for display…},"request_sealed":"<base64, encrypted with the vault key>",
 "state":"pending","decided_by":null,"note":null,"result_ref":null}
```

The exact request to send after approval (`request_sealed`) is encrypted
with the vault key because it may hold unmasked customer data. The display
copy is masked. Command grants use `"type":"command"` and the grant key
instead of a request.

## 9. Security model

### 9.1 Attacker

An AI agent, possibly manipulated by prompt injection from a web page, an
issue or a customer email, running as an ordinary OS user. It can run any
command and any program as that user, read anything that user can read,
write anything that user can write, open network connections, and keep
trying for hours with nobody watching. It cannot break the kernel's user
separation. Root and the admin are trusted. An attacker who is already root
is out of scope (§9.5).

### 9.2 What the attacker can still try, and what v2 does

| # | Attack (as the agent's user) | v2 response |
|---|---|---|
| A1 | Delete or edit the hook in the agent's settings | Managed files are root-owned (`EACCES`). User and project files cannot turn off managed hooks (verified in plan 7). `ConfigChange` records the attempt (Claude Code). |
| A2 | `disableAllHooks` / `--settings` / `codex -c features.hooks=false` | Managed settings outrank them. `core.self` denies the command lines. Plan 7 test per agent. |
| A3 | Replace or shadow the `saiife` binary (`PATH`, alias, a file named `saiife`) | The hook uses an absolute path under root-owned directories. `PATH` is not used. |
| A4 | Inject code into the hook (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`) | Linux binary is static musl (ignores `LD_PRELOAD`). macOS (v2.1) binary uses the hardened runtime (ignores `DYLD_*`). A running session's environment cannot be changed by a script. |
| A5 | Stop or kill the daemon | Another uid: `EPERM`. systemd/launchd restart it if it crashes. While it is down, hooks deny. |
| A6 | Fake the daemon (own socket) | The socket directory belongs to the daemon user; the client checks the owner; the path is fixed in locked mode. |
| A7 | Edit, delete or truncate the audit | Files belong to the daemon user (0640, dir 2750). The agent's user cannot write them. Root edits are caught by `verify` with forwarded checkpoints. |
| A8 | Write fake audit records | `audit.append` accepts only `guard` records, with identity set by the daemon. The agent can make the real `saiife check` judge an invented payload. That only adds a record of a call that did not happen, labelled with the agent's uid (§9.4). |
| A9 | Flood the audit or fill the disk | Per-uid rate cap; free-space floor; both lead to denies (fail closed), and are records. |
| A10 | Read a credential from the vault | Daemon-user file, 0600 in 0700 dir, encrypted at rest. |
| A11 | Read a credential that is still lying around (`.env`, `~/.aws/credentials`) | `core.secrets` blocks the obvious reads (v1). `secret import` removes them. `doctor` finds what is left. A script can read what was not imported: §10. |
| A12 | Call the service directly with a key it found | No key to find once imported. This is the structural fix of v1 §7.1a. |
| A13 | Abuse the gateway: unlisted operation, path tricks, header injection, other hosts | Deny by default; manifest templates; path normalization; header allowlist; host pinning; same-host redirects only. Fuzzed (§13). |
| A14 | Stay within policy but do damage at volume | Limits per uid and session; amount caps (proposed); `ask` for risky operations; lockdown (proposed). |
| A15 | Approve its own request | The approver must be another uid, or re-authenticate (password or Touch ID). `saiife approve` from the same uid is refused and recorded. |
| A16 | Become root (`sudo`), or join a root-equivalent group | Host precondition (§5.6), checked by `doctor`. `core.lock` denies the command lines (proposed). |
| A17 | Switch to a looser environment | `env use` needs admin in locked mode; the environment is bound per scope. |
| A18 | Edit the project config to drop packs or allow services | Project config is add-only in locked mode (§8.2). `core.self` still blocks the write. |
| A19 | Use an MCP server with its own token | v2.0: tools of MCP servers not listed in `[guard.mcp] allow_servers` are denied. Listed servers are an admin-accepted, unbrokered gap: their calls are hooked and audited, and `status` and `doctor` warn about them (decision 10). After v2.0, the MCP gateway (proposed) moves their tokens into the vault. |
| A24 | Use the agent's own model-provider login (read it, or call the provider directly) | **Not prevented, by design** (owner decision 5). `core.secrets` still blocks the obvious reads of the login files (v1). The answer for companies that need it is a local model. |
| A20 | Read the response of a request with secrets in it | The response is masked for vault values and v1 patterns before it leaves the daemon. |
| A21 | Run its own code outside the hook (script, patched agent, nested agent with other settings) | **Not prevented in v2.** That code runs as the user with no keys, cannot touch saiife, and is not audited. v3. `doctor` warns when agent binaries are user-writable. |
| A22 | Send data it can read to any host | **Not prevented in v2.** v3 egress control. Egress recipe (proposed, §6.20) for dedicated accounts on Linux. |
| A23 | Plant persistence that runs later outside a session (cron, user units, login items) | `core.lock` denies the common ways (proposed). A script can still do it: that code is as in A21. |

### 9.3 Fail-closed matrix

| Failure | Claude Code | Codex | Gemini CLI |
|---|---|---|---|
| saiife reports an error (exit 2 + reason) | blocked | blocked | blocked |
| guard engine crash | blocked (worker isolates it; parent denies) | blocked (same) | blocked (same) |
| `check` parent killed or crashes | blocked (`onFailure`) | **runs** | blocked if exit code is not 0 or 1 (unverified for signals) |
| hook timeout (10 s) | blocked | **runs** | **runs** |
| daemon down or not answering in 2 s | blocked (saiife denies) | blocked | blocked |
| binary missing | cannot happen to a locked install (root-owned); blocked by `onFailure` anyway | **runs** | possibly blocked (exit 127, unverified) |

saiife answers well inside the timeout (an internal deadline of 3 s), so the
"runs" cells need the parent process itself to die or hang. These are the
fail-open gaps listed per agent in the docs and in `doctor`.

### 9.4 How much a record proves

- **Connector, approval, secret, policy, daemon and checkpoint records** are
  written by the daemon from its own knowledge. They are authoritative.
- **Guard records** are a claim by a process running as the agent's uid
  that it judged a payload. In honest operation that process is the real
  `saiife check` started by the agent. A determined agent can add records
  for calls it never made, or skip hooks entirely (A21). It cannot remove or
  change records once written. The report labels guard records as "reported
  by the agent's hook", and connector records as "seen by saiife".

### 9.5 What root can do

Root can stop the daemon, read the vault, rewrite the audit and recompute
the chain, and sign new checkpoints with the local key. The only defense is
forwarding: a SIEM copy keeps the checkpoints root signed before the
rewrite, and `verify --external` shows the difference. The docs say this
plainly: v2's audit is tamper-proof against the agent and tamper-evident
against root, provided logs are forwarded.

## 10. Honest limits, per setup

Legend: **covered**, **partly**, **not covered**.

Platforms in v2.0: the two locked columns apply to supported Linux systems
only (Ubuntu 22.04+, Debian 12+, RHEL 9+). Macs, Alpine and containers are
in the Developer column until v2.1 (macOS) or for good (Alpine,
containers). The Personal broker column describes the mode that ships after
v2.0 (decision 7). An agent labelled "not lockable" by the plan 7 gate
(decision 9) falls back to the Developer column for the first two rows,
even on a locked machine.

| Threat | Developer | Personal broker (after v2.0) | Locked (person's account) | Locked (dedicated account) |
|---|---|---|---|---|
| Mistake (destructive or secret-reading command) | covered by packs; fails open | same as developer | **covered**; fails closed (gaps in §9.3) | **covered**; fails closed |
| Helpful bypass (turn saiife off, edit config) | partly (`core.self`, `status`) | partly | **covered** | **covered** |
| Agent obtains a brokered credential | not covered | **partly**: key is in the keychain; a same-user script can read it (Linux) | **covered** once imported; a credential never imported is still readable (A11) | **covered**; the account holds no other credentials |
| Agent uses an external service beyond rules | not covered | partly (no boundary; workflow only) | **covered** for brokered services | **covered** |
| Agent erases or rewrites the audit | not covered (careless edits caught by chain) | same | **covered** (agent); detected (root) with forwarding | **covered** / detected |
| Agent's own script does local damage (`rm -rf` inside a script) | not covered | not covered | **not covered**; damage reaches the person's whole home | **not covered**; damage is limited to what the agent account can write |
| Agent reads the person's other files and logins (SSH keys, browser data, git credentials) | not covered | not covered | **not covered** beyond `core.secrets` | **covered by setup**: the account does not have them |
| Data exfiltration to arbitrary hosts | not covered | not covered | not covered | **partly** with the egress recipe (Linux); otherwise not covered |
| Nested or patched agent without hooks | not covered | not covered | not covered (no keys, no audit) | not covered (no keys, no audit) |
| Model-provider login used or copied by the agent | not covered | not covered | **not covered, by design** (owner decision 5): the agent holds its own model login | **not covered, by design**, unless the agent uses a local model (Ollama, vLLM): then there is no key |
| MCP servers an admin allowed in locked mode | not covered | not covered | **not covered**: unbrokered, but hooked, audited and warned about (decision 10) | same |
| Attacker with root | not covered | not covered | detected with forwarding | detected with forwarding |
| Tools that the agent runs inside its own process without a hook (Codex hosted web search) | not covered | not covered | not covered (not visible to any hook) | not covered |

What still applies from v1 in every setup: the guard's own limits (v1 §7.3
and each pack's "Not covered" section), such as `cd` not being tracked,
dynamic program names, and recursive reads of folders.

`docs/threats.md` gets one section per setup, generated from this table, and
each agent page gets a "Locked mode" section with its row from §6.1.3 and
§9.3 and its lock label from the plan 7 gate.

Wording rule for every docs page, the README and `status` (owner decision
5): never "the agent never holds a credential" on its own. Always "the agent
never holds a credential for a brokered service; it holds its own
model-provider login unless you run a local model".

## 11. Changes to v1 behavior

| v1 | v2 | Why |
|---|---|---|
| Every failure fails open (`error_allowed`) | Locked mode fails closed (`error_denied`); developer mode can opt in with `fail = "closed"` | v1 §1.2 rule 4: nobody is there to notice in unattended use. |
| Hook command found via `PATH` | Managed hooks use `/opt/saiife/bin/saiife` | `PATH` belongs to the agent's user. |
| `SAIIFE_AUDIT_DIR`, `SAIIFE_DATA_DIR` change locations | Ignored in locked mode | The agent's user controls its environment. |
| Audit in the user's data dir, written by the hook | Locked: written by the daemon to `/var/log/saiife/audit`; `saiife audit` reads through the daemon | v1 §1.2 rule 6. |
| Record `v = 1` | `v = 2` with `seq`, `prev`, `kind`, `policy`, …; v1 fields kept | v1 §9.3. 0.1.0 readers still show v2 files. |
| Hooks match a fixed list of tools | Locked: all tools; MCP tools denied unless their server is in `[guard.mcp] allow_servers` | Principle 3; full audit visibility. |
| Project `locked` key reserved | Project `locked` ignored; `/etc/saiife/config.toml` `locked = true` decides | A project must not lock or unlock itself. |
| Project config sets the opt-in packs | Locked: add-only | v1 §9.1. |
| `init --off` removes hooks | Locked: removes leftover project hooks only; managed hooks need `system uninstall` (root) | v1 §9.1. |
| Engine abort not caught | Locked: worker process; abort means deny | Carry-over. |
| Shell payload over 1 MiB logged with empty input | Locked: deny (`error_denied`) | Fail closed. |

Developer mode keeps every other v1 behavior unchanged.

## 12. Migration from v1

1. **Upgrade the binary.** Developer setups keep working. New records are
   `v = 2` (chained, in the same user folder). Old files stay as they are.
2. **Go locked** (supported Linux in v2.0; macOS from v2.1):
   `sudo saiife system install --agents claude,codex,gemini
   --approvers group:saiife-approvers`. Then:
   - v1 project hooks stay in place but go quiet for agents that now have a
     managed hook (§6.1.1). `saiife init --off` in each project removes them
     (optional). `doctor` lists projects that still have them.
   - The old per-user audit is not imported (it was user-writable, so it
     cannot be trusted). It stays readable through `saiife audit`, labelled.
     The new chain starts with a genesis record.
   - Run `sudo saiife doctor` and fix every failure (sudo rules, groups,
     agent binary ownership).
3. **Move credentials:** `sudo saiife secret import --user <name>` for each
   agent user. For each service: `sudo saiife connect <service>`, edit the
   generated policy, `saiife policy test`, `saiife policy reload`. Rotate
   any credential that was in the agent's reach before (it may already have
   been copied). `doctor` reminds you.
4. **Recommended for unattended use:** create a dedicated agent account,
   run the agent there, scope it, and apply the egress recipe (Linux).
5. **Fleets:** in v2.0, run `system install --non-interactive --config
   <file>` from the configuration tool (for example Ansible). Packages and
   MDM recipes (proposed, after v2.0, §15 plan 18) make this a standard
   install.

## 13. Testing

- **Everything in v1 stays green**, including the offline CI job. Connector
  tests run against mock HTTP servers on loopback inside the network
  namespace (`unshare -rn` with `lo` brought up), so v2 tests never reach the
  internet.
- **Chain:** unit tests for each tamper type (edit one byte, delete a line,
  insert, reorder, truncate the tail, swap month files, forged checkpoint,
  key rotation); `verify --external` catches a cut-off tail; v1 files are
  reported as unchained; 0.1.0's reader (pinned test binary) reads a v2 file
  without errors.
- **Daemon integration:** CI creates a real daemon user and an agent user
  (GitHub Actions Ubuntu runners have sudo), installs with `system install`,
  and runs the suite as the agent user. v2.0 runs it on Ubuntu 22.04 and
  24.04 runners (covering systemd 249 with the plain key file and systemd
  255 with `LoadCredentialEncrypted`), plus Debian 12 and RHEL 9 (UBI with
  systemd, or Rocky) in a VM job before each release. The macOS job joins in
  v2.1. Macs keep running the developer-mode suite in v2.0.
- **Red-team suite (core acceptance test):** a scripted attacker running as
  the agent user tries every attack in §9.2 by script, not by tool call. For
  v2.0 that is A1–A18 and A20, plus these cases for the v2.0 additions:
  self-approving a command grant (`[guard] ask`), reusing a used or expired
  grant, turning lockdown off as a non-approver, changing the amount cap by
  splitting one refund into many, reading or editing the polkit action file,
  using an MCP server not in `allow_servers`, and being listed in two
  scopes (policy refused). Every attempt must fail, and the ones the daemon
  can see must be recorded. For A19 the suite checks that unlisted MCP
  servers are denied and listed ones are warned about. A21–A24 are asserted
  as "known not covered", so the docs and the tests agree.
- **Re-authentication fallback:** with `pkcheck` removed, `same_user =
  "reauth"` refuses a same-uid approval, a second uid can still approve, and
  `doctor` warns (decision 3).
- **Supported-system check:** `system install` refuses on Alpine and inside a
  container (developer mode only), with a clear message (decision 8).
- **Fail-closed:** daemon stopped → each agent's fixture payload gets
  exit 2; worker killed with SIGSEGV/SIGKILL → deny; budget exceeded →
  deny; disk-floor reached → deny.
- **Policy:** table tests for capability matching, order (deny > ask >
  allow > default deny), add-only project merge, environment overlays,
  effective-policy hash stability, refusal of invalid reloads.
- **Connectors:** every manifest loads; per operation, request building
  (path, query, headers, auth placement) against a golden file; pagination;
  masking of vault values in responses; redaction (proposed; in v2.0);
  amount caps (proposed; in v2.0).
- **Fuzzing (`cargo fuzz`):** IPC frame decoder, proxy path matcher,
  manifest parameter validation, HTTP request parser. Run in CI for a fixed
  time on each PR, longer nightly.
- **Approvals:** create, approve, reject, expire; the stored request is sent
  unchanged; the same uid is refused without reauth; reauth on Linux with a
  polkit test agent (CI). macOS reauth is tested by hand in v2.1.
- **Agents, live:** `scripts/live-check-locked.sh` per agent: a managed hook
  fires; user/project/command-line attempts to disable it fail; the
  fail-closed matrix (§9.3) cells marked "blocked" hold. Run by hand before
  each release (like the v1 live checks), and recorded as fixtures. Its
  result sets each agent's lock label (decision 9).
- **Performance:** `scripts/bench-check.sh` extended for locked mode: p95 of
  a full hook call (worker + ack) under 40 ms.

## 14. Definition of done (v2.0)

1. `sudo saiife system install` works on Ubuntu 22.04 and 24.04, Debian 12
   and RHEL 9 (x86_64 and arm64, systemd), using `LoadCredentialEncrypted`
   where systemd is 250 or later and the plain key file otherwise.
   `system uninstall` removes exactly what it installed. On Alpine, in
   containers and on macOS, `system install` refuses with a clear message,
   and developer mode works as in v0.1.0, plus the chained log.
2. Each of Claude Code, Codex and Gemini CLI has a lock label from the plan 7
   gate (decision 9). Every agent labelled "locked" or "locked with caveats"
   passes the live check script on Linux. Any agent labelled "not lockable"
   is labelled so in `status`, `doctor` and its docs page, and no lock claim
   is made for it.
3. The red-team suite passes: every attack and every v2.0-addition case in
   §13 fails when run as the agent's user, and A21–A24 are documented as not
   covered.
4. Locked mode fails closed in every case §9.3 marks "blocked", and the
   fail-open cells are documented per agent.
5. `saiife audit verify` detects every tamper type in §13, including a
   cut-off tail with a forwarded copy. Forwarding to syslog, file and HTTPS
   works and survives an outage without gaps.
6. Connectors: Shopify, HubSpot, GitHub and generic HTTP work through the
   CLI and the HTTP gateway, reads and writes, with deny-by-default policies,
   limits, amount caps, field redaction and masked responses. No connector
   credential is readable by the agent's user.
7. `ask` works end to end, for connector requests and for commands: request,
   notification, approval by a second uid or by the same uid with polkit
   re-authentication, daemon sends the stored request (or the grant is used),
   result picked up by the agent. Without polkit, only a second uid can
   approve, and `doctor` says so.
8. `saiife doctor`, `core.lock`, `saiife lockdown`, `saiife policy check` and
   `policy test` work as specified, including overlapping-scope refusal.
9. In locked mode, MCP tools are denied unless their server is listed, and
   `status` and `doctor` warn about each listed server.
10. The report shows chain status, connector activity, approvals and the
    policy in force.
11. `docs/threats.md` states, per setup in §10, what is and is not covered,
    including that the agent keeps its own model-provider login. Each
    connector and agent page has its locked-mode section. The egress recipe
    page is published and tested on one supported system.
12. A 5-minute demo runs end to end on Linux: install locked → agent tries
    to remove the hook, kill the daemon and read the Shopify token (all
    fail) → agent lists orders (allowed) → agent edits a product (pending,
    approved by a second user) → `audit verify` → report.
13. Full test suite passes with networking disabled.

**v2.1** is done when locked mode meets points 1–4 and 7 on macOS (Intel and
Apple Silicon), with a signed and notarized binary. The full v2 series is
done when every v1 §9.5 v2 row has shipped: all connector waves,
collections, cloud credentials and environments (plans 14–15), plus the
after-v2.0 items in §15.

## 15. Delivery plans

The v1 track already uses plan 6 (v0.1.1, v1 gaps), so v2 starts at plan 7.
Each plan ends with working, tested software, and is written in full only
when the one before is done (as in v1). Estimates are in weeks of evenings,
as in v1.

### 15.1 v2.0 (release 0.2.0, locked mode on Linux)

| # | Plan | Spec sections | Delivers | Estimate |
|---|---|---|---|---|
| 7 | Live lock verification gate + housekeeping | §3 carry-over, §6.1.3, §8.3 | Managed settings verified live for all three agents on a supported Linux system, as fixtures: precedence, `disableAllHooks` vs managed hooks, `onFailure`, `ConfigChange`, Codex `requirements.toml` path and `[features]` pin, Gemini system settings, hooks toggle and env override, MCP restriction keys. Sets each agent's lock label (decision 9). Housekeeping carry-overs. Updated research docs. | 1 |
| 8 | Audit v2 + chain (developer mode) | §6.4, §8.5, §8.6, §6.19 (chain status, policy per decision) | Record v2, flock chain, `audit verify`, `policy` hash per record, 0.1.0 reader compatibility test, report additions. Works on Linux and macOS. | 1 |
| 9 | Daemon + locked mode (Linux) | §4, §5.1–5.2, §5.4–5.6, §6.1–6.3, §6.16, §6.17, §7 (system, daemon, doctor), §11 | `crates/ipc`, `crates/policy` (incl. one scope per uid), `crates/daemon` (control server, audit writer, checkpoints), `system install`/`uninstall` for systemd (both vault-key variants, supported-system check), managed hooks, fail-closed `check` with worker, add-only project merge, `[guard.mcp]` allow list with warnings, `doctor`, `core.lock`, red-team A1–A10, A16–A18 | 2 |
| 10 | Vault + gateway + connector wave 1 | §6.6–6.9, §6.14 (`run --secret`), §8.4, §8.8, §8.9 | `crates/broker`, vault, `secret`, `connect`, `api`, HTTP gateway, policy and limits, amount caps, sessions, masking, field redaction, Shopify, HubSpot, GitHub (reads and writes), generic HTTP, `secret import`, red-team A11–A14, A20, fuzzing | 3 |
| 11 | Approvals + notifications + lockdown | §6.10, §6.18, §8.10 | `ask` for connectors and commands, approvers, polkit re-authentication and its fallback, notifications, lockdown, red-team A15 and the addition cases | 1.5 |
| 12 | Forwarding + auditor access + release 0.2.0 | §6.4.5, §6.5, §6.20, §14 | syslog/file/HTTPS forwarding, `verify --external`, auditor group, `audit.query`, `policy check`/`test`, docs (threats, agents, connectors, egress recipe), demo, release 0.2.0 | 1.5 |

**v2.0 (plans 7–12): about 10 weeks of evenings.** Moving macOS locked mode
out saves about half a week in plan 9 and half a week in plan 11. Adding
amount caps, redaction, `policy check`/`test` and the egress page to v2.0
costs about the same, so the total stays close to the first draft.

### 15.2 After v2.0

| # | Plan | Release | Delivers | Estimate |
|---|---|---|---|---|
| 13 | macOS locked mode | v2.1 | §5.3: `_saiife` user, launchd daemon, `LOCAL_PEERCRED`/`LOCAL_PEERPID`, Developer ID signing, hardened runtime, notarization in release CI, macOS authorization re-authentication, macOS live lock checks and CI job | 2 |
| 14 | Connector waves 2 and 3 + environments + collections | v2.x | 14 connectors (about 1 evening each; Salesforce OAuth2 and Email take longer), environments, collections | 3 |
| 15 | Cloud connectors | v2.x | AWS SigV4 signing and STS mode, GCP and Azure tokens, cloud docs pages | 2 |
| 16 | Personal broker mode | v2.x | `saiife daemon --user`, keychain vault (macOS Keychain, Secret Service), developer-mode `connect`/`secret` (decision 7) | 1 |
| 17 | MCP (proposed) | v2.x | `saiife mcp` server, MCP gateway for third-party servers, managed MCP restrictions moved behind the broker | 1.5 |
| 18 | Fleet packaging (proposed) | v2.x | `.deb`, `.rpm`, and a signed, notarized macOS `.pkg` (after plan 13); MDM recipes (Jamf, Intune, Ansible) | 1 |

**Full v2 series (plans 7–18): about 20.5 weeks of evenings.** Plans 14–18
can be reordered by customer demand. Plan 13 comes first after v2.0 because
it was promised as v2.1.

## 16. Proposed additions and cuts

### 16.1 Proposed additions and where they ship

| Addition | Section | Ships | Why, in one line |
|---|---|---|---|
| `saiife doctor` | §6.16 | v2.0 (owner decision 1) | The lock holds only when host preconditions hold, and someone has to check them. |
| `core.lock` pack | §6.17 | v2.0 (owner decision 1) | Clear denials for sudo, service control and persistence, instead of an agent looping on permission errors. |
| Approval for commands (`[guard] ask`) | §6.10.4 | v2.0 (owner decision 1) | An unattended agent blocked by a rule otherwise gives up or looks for a way around. |
| Notifications (webhook, SMTP, command) | §6.10.3 | v2.0 (owner decision 1) | Without them, `ask` stalls silently and limit hits and chain breaks go unseen. |
| Lockdown kill switch | §6.18 | v2.0 (owner decision 1) | One command for the person on call to stop a misbehaving unattended agent. |
| Amount caps for money-moving operations | §6.9.4 | v2.0 (owner decision 1) | A refund ceiling that does not depend on the agent's judgment. |
| `saiife policy check` / `policy test` with `[[example]]` | §7, §8.1 | v2.0 (owner decision 1) | Policies kept in git need a CI check, like pack examples. |
| Response field redaction | §6.7.3 | v2.0 (designer's call: about one evening inside plan 10's masking pass) | Data minimization for the DPO: the agent gets only the fields the task needs. |
| Egress recipe for dedicated agent accounts (docs only) | §6.20 | v2.0 (designer's call: one docs page in plan 12) | Narrows the exfiltration gap for the recommended unattended setup at the cost of a page. |
| `saiife mcp` (connectors as MCP tools) | §6.15 | after v2.0 (owner decision 1), plan 17 | Agents call typed MCP tools more reliably than CLI lines. |
| MCP gateway (third-party MCP servers run by the daemon) | §6.15 | after v2.0 (owner decision 1), plan 17 | MCP servers keep tokens in user config, which is the leak v2 closes elsewhere. |
| Fleet packages (.deb/.rpm/.pkg) + MDM recipes | §15.2 | after v2.0 (owner decision 1), plan 18 | Companies roll out through MDM, which expects packages. |

### 16.2 Considered and cut

| Idea | Why cut |
|---|---|
| Signed policy bundles | MDM and root-owned files already give integrity on the machine. Signing pays off with a central hub (after v3). |
| Local admin web dashboard | A listening web server is attack surface. The HTML report and `saiife approvals` cover the need. |
| Redacting secrets in the agent's own context or transcript | Hooks cannot reliably rewrite tool output in all three agents. The broker masks responses instead, and the agent never gets keys in the first place. |
| Approval by clicking a link in a notification | Needs inbound network or a hosted relay. Approvals stay on the machine. The hosted relay is v3. |
| Daemon-side guard evaluation | Needs the agent user's view of the filesystem, and gains nothing against an agent that skips the hook (§9.4). |
| Model-provider key brokering | Not in v2 (owner decision 5). The agent holds its own model login, or the company runs a local model. |

## 17. Open questions

All six questions of the first draft are answered (§0, decisions 1–5 and 9).
None is open for v2.0. These remain, for later plans:

1. **macOS minimum version for v2.1** (plan 13). The proposal is the oldest
   macOS that Apple still updates when plan 13 starts.
2. **Which wave-2 and wave-3 connectors come first** (plan 14), by customer
   demand.

## 18. v3 compatibility

v2 must not block the isolated runner (v1 §9.4). The design keeps these
doors open:

- The daemon already runs as its own user and keeps everything the agent
  must not touch (binary, policy, vault, audit) outside the agent's
  identity. The v3 runner only has to keep those paths out of the sandbox.
- The gateway is a Unix socket. v3 mounts `gateway.sock` into the sandbox as
  its only route to external services, and the egress rules allow it.
- `session` in IPC frames and records is already there. v3 fills it with a
  runner-issued identity, and attribution (§6.9.3) becomes authorization.
- `[[scope]]` is the precursor of v3 profiles. The key `profile` is reserved
  in `/etc/saiife/config.toml` and in `[[scope]]`, and v2 refuses it as
  "reserved for v3".
- Approvals, limits, lockdown and the audit chain are daemon features, so
  `saiife sessions`, `saiife stop <session>` and flows in v3 reuse them
  unchanged.
- Nothing in v2 stores state in the agent user's home that the daemon needs.
