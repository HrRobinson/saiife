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
| 2 | Linux first. In v2.0, locked mode is **Linux only**. macOS locked mode (Developer ID, hardened runtime, notarization, launchd, `LOCAL_PEERCRED`, macOS re-authentication) moves to **v2.1**. Macs keep v1 developer mode in v2.0. Windows follows in v2.2 (§5.3a). | Owner decision (2026-10-19) | §1.1, §5.3, §14, §15 |
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
| **Developer** (v1 mode, still the default) | the developer, no root | the developer | a person nearby; same guarantees as v1 plus a hash-chained log | v2.0: Linux (any, including Alpine and containers) and macOS. Windows from v2.2 (§5.3a) |
| **Personal broker** (after v2.0, decision 7) | the developer, no root | the developer | trying connectors on your own machine; **not a security boundary** (§10) | later |
| **Locked** | an admin, as root | the person's own account | company laptops and workstations, attended or unattended | v2.0: Linux only (Ubuntu 22.04+, Debian 12+, RHEL 9+, systemd required). macOS in v2.1. Windows in v2.2 (§5.3a). |
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
- Signed policy bundles, a local web dashboard and transcript redaction:
  considered and cut (§16.2).
- Brokering the agent's model-provider key (owner decision 5).

Designed here, but shipped after v2.0 (§15): macOS locked mode (v2.1),
Windows developer mode (v2.2, plan 19a) and Windows locked mode (v2.2,
plan 19b; §5.3a), personal broker mode, `saiife mcp`, the MCP gateway,
fleet packages and MDM recipes, connector waves 2 and 3, cloud connectors,
environments and collections.

## 2. Decisions

| # | Decision | Chosen | Why |
|---|---|---|---|
| D8 | Privileged component | A long-running daemon, `saiifed`, running as a **dedicated unprivileged system user** (`saiife` on Linux, `_saiife` on macOS, `NT SERVICE\saiifed` on Windows, a virtual service account). Root is needed only to install it. | Least privilege. A setuid helper adds a root attack surface on every hook call and is awkward on macOS. A root daemon parses agent input as root. §5.5. |
| D9 | IPC | Unix domain sockets in a directory owned by the daemon user. Callers are identified by kernel peer credentials (uid, pid). No TCP by default. On Windows: a named pipe, `\\.\pipe\saiife`, with the client identified by impersonation (§5.3a). | Loopback TCP cannot tell callers apart. A socket path the agent's user cannot create cannot be spoofed. |
| D10 | Where guard decisions are made | In the hook process, as in v1. The daemon writes the record and acknowledges it before the hook answers. | Path checks need the agent user's view of the filesystem. A forged client gains nothing it could not get by skipping the hook (§9.4). Keeps the 50 ms budget. |
| D11 | Locked-mode failure | Fail closed: any error, missing acknowledgement from the daemon, or exceeded budget means deny and `error_denied`. | v1 §1.2 rule 4. |
| D12 | Lock location | Hooks go into each agent's system-level policy file (managed settings). The binary goes in `/opt/saiife/bin/saiife`, and the hook calls it by absolute path. On Windows: `C:\ProgramData\saiife\bin\saiife.exe` (§5.3a). | v1 §9.1. On macOS with Homebrew, `/usr/local/bin` is often owned by the user, so it cannot hold a locked binary. |
| D13 | Vault | A file encrypted at rest, owned by the daemon user (locked mode). The OS keychain is used in personal broker mode (after v2.0). | The OS keychain's per-user model cannot keep a secret from the same user's processes. |
| D14 | Connector shape | Declarative TOML manifests embedded in the binary (like packs). Operations are typed and map to capabilities (`orders:read`). A generic HTTP connector covers the rest. | Manifests are reviewable, testable without network, and cheap to add (about 1 evening each for most services). |
| D15 | Agent access to connectors | v2.0: `saiife api` on the command line and an HTTP gateway on a Unix socket (`curl --unix-socket`, SDKs via proxy paths; on Windows there is no `gateway.sock`, only loopback TCP with a bearer token, §5.3a.2). After v2.0: an MCP server **(proposed addition)**. | The CLI works for every agent today. HTTP lets existing SDKs work. MCP is how agents prefer to call tools. |
| D16 | Approvals | `ask` rules create a request. The agent gets "pending #N" right away and never waits inside a hook. Only an approver identity the agent's user cannot be can decide (§6.10). | Hooks have timeouts. An approval the agent could give itself is worthless. |
| D17 | Audit format | JSONL, `v = 2`, one global hash chain per machine (`seq`, `prev`), signed checkpoints, v1 fields kept so 0.1.0 readers still work. | v1 §9.3. |
| D18 | State store | Files only (JSON and JSONL), no database. Rate-limit counters are rebuilt from the audit log at startup. | Keeps the static musl build and the "one binary" rule (v1 D4). The audit log is the source of truth. |
| D19 | One binary | Still one `saiife` binary. `saiife daemon` is a subcommand. | v1 D4. Install and upgrade stay one file. |
| D20 | Scope of a caller | Authorization is by **OS user** (uid), through exactly one `[[scope]]` per uid (decision 6). Project paths and agent sessions are used for attribution and limits only; they never select a scope or an environment. | uid is the only identity the kernel vouches for in v2. v3 adds runner-issued session identity. |
| D21 | Platforms for locked mode | v2.0: Linux with systemd (Ubuntu 22.04+, Debian 12+, RHEL 9+). v2.1: macOS. v2.2: Windows 11 23H2+ and Windows Server 2022+, x64 and ARM64 (§5.3a). | Owner decision 2, builder's call 8. One service manager and one peer-credential API to get right first. Windows added on 2026-10-30 (owner decision); until then it was out of scope with no recorded reason. |

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
  win/      NEW (v2.2): Windows FFI, the second crate allowed unsafe (§5.3a)
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
| `/opt/saiife/bin/saiife` | root:root | 0711 | the binary (static musl); execute only for others (plan 20), so no process of the agent's user can trace or read a running hook |
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

**Note (plan 13).** Built in v2.1, with these departures and details:

- **Socket dir** (plan 13 decision 2): `/var/db/saiife-run` (0755
  `_saiife`), not `/var/run/saiife`. `/var/run` is root:daemon 0775, so the
  daemon user cannot create a dir there at start, and it is cleared at boot.
  Install creates the dir; it lasts across reboots, and the daemon replaces
  stale sockets at bind. The client checks the dir owner as on Linux, and
  `[daemon] socket_dir` defaults to it on macOS (§8.1).
- **Vault key mode:** `installed.toml` records `vault_key = "daemon_file"`
  for `/var/db/saiife/keys/vault.key` (0400 `_saiife`, created with
  `O_EXCL|O_NOFOLLOW` and changed through its descriptor). On macOS
  `installed.toml` has `systemd = 0` and gains `auth_rights`.
- **Daemon log:** the plist sends stderr to `/var/log/saiife/daemon.log`
  (0640), because macOS has no journal for it.
- **`ThrottleInterval = 1`** in the plist, like `RestartSec=1` on Linux.
- **Claude Code** (decision 11): the drop-in dir
  `/Library/Application Support/ClaudeCode/managed-settings.d/`
  (`50-saiife.json`, `60-saiife-mcp.json`), as on Linux, not the whole file.
  If the owner's macOS live check shows that drop-ins are ignored there,
  install switches to `managed-settings.json` and refuses a foreign one.
  Install and `doctor` warn when the MDM profile
  `/Library/Managed Preferences/com.anthropic.claudecode.plist` exists.
- **Accounts:** `_saiife` (user and group) and `_saiifeaudit`, local
  directory records only; ids are picked free among both users and groups
  in 200–400; an existing hidden `_saiife` with `/usr/bin/false` is reused,
  a login-capable or non-local one is refused.
- **The `nix` / `saiife-darwin` boundary** (decision 1): `LOCAL_PEERCRED`,
  `LOCAL_PEERPID`, `getpwnam_r` and `getgrnam_r` come from `nix`'s safe
  API. `sysctl(KERN_PROC_PID)` and, since plan 21,
  `sysctlbyname("net.inet.tcp.pcblist_n")` (the co-signer's asker, §6.1.1)
  are the two FFI calls, in the crate
  `saiife-darwin`, the only crate besides `saiife-win`'s `ffi` module allowed `unsafe`; `libc` has no Apple
  `kinfo_proc`, so the crate writes out xnu's LP64 layout with size and
  offset asserts. The workspace lint `unsafe_code = "forbid"` and
  `scripts/check-unsafe.sh` (CI) enforce the boundary; `unsafe` that a
  dependency's macro expands into is not caught.
- **`LOCAL_PEERPID` is the socket's last pid**, not strictly the
  connecting process, so on macOS nothing is granted on a pid (§6.3,
  §6.9.3, §6.10.2).
- **Minimum:** macOS 15 (§17 question 1).
- **Signing:** install requires the hardened runtime and a release build;
  an ad-hoc signature only warns (§14).
- **Same-user approval is off on macOS** (§6.10.2).
- **System Integrity Protection is required** (owner ruling, plan 13 CI):
  the hardened runtime keeps `DYLD_INSERT_LIBRARIES` out of the hook only
  with SIP on; on the SIP-disabled CI runners an injected library ran
  inside the ad-hoc signed hook. Install refuses (exit 2, before any
  change) and `doctor` fails `system.sip` unless `csrutil status` prints
  exactly `System Integrity Protection status: enabled.`; disabled,
  unknown, a custom configuration or an error is not enabled. A build with
  debug assertions honours `SAIIFE_TEST_ALLOW_SIP_OFF=1` (CI only: install
  warns, `doctor` warns); a release build never reads it.

### 5.3a Files and permissions: Windows (v2.2)

Developer mode on Windows needs no admin rights and ships in v2.2 (plan
19a). Locked mode on Windows is designed here and built in plan 19b. The
layout is fixed now so that 19a does not block it. This section is numbered
5.3a because §5.4–§5.6 are cited from about 400 places in code and docs.
Windows follows the Linux design (§5.2) with the differences below.

**Built (plan 19b).** Locked mode on Windows is built and ships **as a preview**
(owner ruling 2026-11-06), because of A25 (§9.2): a process of the agent's own user
can end the hook with `TerminateProcess(hook, 0)`, which every agent reads as allow,
and nothing is recorded. CI measured it on `windows-2022` and `windows-2025`. Since
plan 21 the preview covers Codex and Gemini CLI only: for Claude Code the service
judges each call itself (§6.1.1), and it is not a preview: `locked-windows`
showed the forged allow and the hook kill denied on `windows-2022` and
`windows-2025` (§13, CI run 42673682022). `doctor` prints
`locked.preview` when Codex or Gemini CLI is installed, or when the co-signer is not
whole (§6.16), and the docs say "preview for Codex and Gemini CLI" wherever they offer
Windows locked mode. What changed from the design while it was built:

- **Approvals (W16).** Same-user approval is off, as on macOS (owner ruling
  2026-11-05): approvals need a second account, from a separate session. The planned
  password re-authentication and its `LogonUserW` call were dropped.
- **ACLs act on handles (W1).** `GetSecurityInfo` and `SetSecurityInfo` work on a
  handle opened without following a reparse point; before a set,
  `GetFileInformationByHandle` refuses a hard-linked file and `GetFinalPathNameByHandleW`
  checks that the handle is the path asked for. CI showed that a set reaches inheriting
  children but not protected ones, so install walks the tree (`set_sddl_tree`), and that
  files drop `OI` and `CI` (`actual_file_ok`). `LA`, the built-in Administrator, counts
  as an admin owner.
- **Peers (W11, W12).** A pipe peer is an admin, uid 0, only at High integrity or above
  with no restricted SIDs; the same holds for a lowered SYSTEM token. The pipe has at
  most 254 instances. Approver names and `[[scope]] users` match by SID;
  `group:` approvers count by the token's groups only.
- **Service (W10).** The restart action repeats for every failure past the third, so
  the restarts never run out.
- **The eval worker** runs in a kill-on-close job object (`job.rs`, three more FFI
  calls), so a killed hook leaves no worker behind.
- **Personal broker (W25).** It runs only as a person's account (local, domain or
  Entra ID); every virtual account and AppContainer is refused.
- **MSI (W20).** Rollback actions undo the install, upgrade and removal actions.
- **Measured, not holes:** `DefineDosDevice` on `C:` is refused to a standard user
  (error 5); a DLL planted beside a copy of `saiife.exe` is not loaded; share-mode-0
  opens of `saiife.exe` or `config.toml` do not stop hooks; a standard user cannot stop,
  reconfigure or delete the service. The cross-user `TerminateProcess` seen in CI comes
  from the test accounts sharing the runner's logon SID (§9.2, A25).
- **Known limits, not verified:** OpenSSH sessions are probably denied by W11's `NU`
  deny, so hooks deny there; restricted and low-integrity tokens keep their other
  groups, so `group:` policy matches them.
- **Plan 20.** For Claude Code a killed hook is now denied by the co-signer, and for
  every agent it is recorded (`no_verdict`). A forged allow is still not prevented: any
  process of the agent's user can begin, bind and append an allow, then end the hook,
  with no code injection. Plan 20 left Windows locked mode a preview for that. See A25
  (§9.2).
- **Plan 21.** The co-signer allows only when the hook's verdict and the service's
  own, lexical judgment of the same input agree (§6.1.1). A forged allow of a call
  the policy denies is denied and recorded (`rejudge_denied`, §8.5). The co-signer
  finds who asks through the TCP table and the process tree (§5.3a.2, W13). Windows
  locked mode stays a preview for Codex and Gemini CLI, which have no HTTP hook. For
  Claude Code it is not a preview: `phase_forge` (§13) was green on both
  `locked-windows` cells (CI run 42673682022).

**Platform (W2).** Windows is a third value of `Platform`, with the name
`windows`. Developer mode is v2.2 too, and needs no admin.

#### 5.3a.1 Layout

Supported (W2): Windows 11 23H2 (build 22631) or later, and Windows Server 2022
(build 20348) or later, on x64 and ARM64. Windows 10 is out, because its
consumer ESU ended on 2026-10-13.

| Linux | Windows |
|---|---|
| developer audit dir `~/.local/share/saiife/audit` | `%LOCALAPPDATA%\saiife\audit` (`dirs::data_local_dir()`) |
| `/opt/saiife`, `bin/`, `bin/saiife` | `C:\ProgramData\saiife`, `…\bin`, `…\bin\saiife.exe` |
| `/etc/saiife`, `config.toml`, `policy.d`, `installed.toml`, `ca/`, fleet dir | `C:\ProgramData\saiife\etc`, `…\etc\config.toml`, `…\etc\policy.d`, `…\etc\installed.toml`, `…\etc\ca`, `…\etc\fleet` |
| `/var/lib/saiife`, `keys/`, audit key, vault key | `C:\ProgramData\saiife\state`, `…\state\keys`, `…\state\keys\audit.ed25519`, `…\state\keys\vault.key` |
| `/var/log/saiife`, audit dir, daemon log | `C:\ProgramData\saiife\log`, `…\log\audit`, `…\log\daemon\daemon.log` |
| `/run/saiife` and the control socket | none. The control endpoint is the pipe `\\.\pipe\saiife` (§5.3a.2) |
| systemd unit | the service `saiifed` (display name `saiife daemon`) in the service manager |
| Claude managed settings | `C:\Program Files\ClaudeCode\managed-settings.d\50-saiife.json` and `60-saiife-mcp.json` |
| Codex `requirements.toml` | `C:\ProgramData\OpenAI\Codex\requirements.toml` |
| Gemini system settings | `C:\ProgramData\gemini-cli\settings.json` |
| package binary (plan 18) | `C:\Program Files\saiife\saiife.exe` (the MSI's own copy) |
| polkit files and `pkcheck` | none |

Rules:

- **Developer mode data dir (W3).** It is the local `%LOCALAPPDATA%`, not
  the roaming `%APPDATA%`, so a roaming profile never syncs the audit. The
  files get no explicit ACL. A profile's `AppData\Local` already allows only
  the user, SYSTEM and Administrators. That matches the Linux 0700/0600
  intent. `SAIIFE_DATA_DIR` and `SAIIFE_AUDIT_DIR` still win.
- **Developer config.** The hook reads `C:\ProgramData\saiife\etc\config.toml`
  (Linux: `/etc/saiife/config.toml`).
- **The locked binary is not under `C:\Program Files` (W9).** The hook
  command must survive Git Bash, PowerShell and cmd without quoting. A path
  with a space does not. The hook command is
  `C:/ProgramData/saiife/bin/saiife.exe check --managed --hook-exit --agent <a>`.
  It has forward slashes and no spaces, so no shell eats a backslash and
  none needs quotes. In developer mode, the project hook stays
  `saiife check --hook-exit --agent <a>` through `PATH`.
- **Default system folders only.** Install refuses unless the registry says
  `ProgramFilesDir` is `C:\Program Files` and `ProgramData` is
  `C:\ProgramData`: `non-default system folders are not supported in this
  version`. It never reads them from environment variables.
- **The service (W10).** Name `saiifed`, own process, auto start, logon
  account `NT SERVICE\saiifed`, binary
  `C:\ProgramData\saiife\bin\saiife.exe` with arguments `daemon --system`,
  no password. Failure actions: three restart actions after 1 s each, reset
  after 86 400 s, also on non-crash failures. The service manager repeats the
  last action for every failure past the third, so the restarts never run out.
  This is `Restart=always`, `RestartSec=1`. The service's own DACL is set with `sc.exe sdset saiifed
  D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWLORC;;;AU)`.
  That is the Windows default plus query rights for Authenticated Users.
  Only SYSTEM and Administrators can stop, pause, reconfigure or delete it.
  `SERVICE_CONTROL_PARAMCHANGE` reloads the policy (SIGHUP on Linux). Stop
  and shutdown are a clean stop (SIGTERM). The daemon's stderr goes to
  `C:\ProgramData\saiife\log\daemon\daemon.log`. At service start,
  `SetStdHandle(STD_ERROR_HANDLE, <file>)` points stderr there. A file over
  10 MiB is renamed to `daemon.log.1` in the same dir. The log has its own
  dir because the service SID has only read and execute on `…\log`, so it
  could neither rename the file nor create a missing one there.

References: Microsoft Learn, "Service accounts"; code.claude.com/docs/en/settings,
code.claude.com/docs/en/managed-settings; Codex managed configuration
(learn.chatgpt.com/docs/enterprise/managed-configuration); Gemini CLI
configuration (geminicli.com/docs/reference/configuration).

#### 5.3a.2 Identity and IPC

| Linux | Windows |
|---|---|
| daemon user `saiife` | the virtual account `NT SERVICE\saiifed` (W10) |
| group `saiife-audit` | the local group `saiife-audit` |
| Unix socket, peer uid and pid from the kernel | the named pipe `\\.\pipe\saiife`, the caller's SID and groups from its token (W11) |
| uid | `uid_of(sid, elevated_admin)`, plus `sid` in audit records (W12) |
| gateway on a Unix socket and TCP | loopback TCP with the bearer token only (W13) |
| personal broker, Secret Service | personal broker, Credential Manager (W25) |
| root to install | an elevated Administrators token to install (W26) |

- **Why a virtual account (W10).** It has its own SID, so there is no shared
  `LocalService` identity. It has no password to manage. It cannot log on
  interactively. It needs no user creation. A dedicated local user would
  need a password and its own hardening. The account's SID is
  `service_sid("saiifed")`, a pure function, so every ACL can name it
  without a lookup. The service SID type is unrestricted.
- **The control pipe (W11).**
  - The security descriptor is
    `O:<S>G:<S>D:P(D;;GA;;;NU)(A;;GA;;;<S>)(A;;GA;;;SY)(A;;0x12019b;;;BU)`,
    with `<S>` the service SID.
  - `0x12019b` is `FILE_GENERIC_READ | FILE_GENERIC_WRITE` without
    `FILE_APPEND_DATA`. For a pipe, `FILE_APPEND_DATA` is
    `FILE_CREATE_PIPE_INSTANCE`. So a client may connect, but it can never
    add a server instance. Network logons are denied, and
    `reject_remote_clients(true)` is set too.
  - **Squatting.** The first instance is created with
    `first_pipe_instance(true)`. If the name already exists, someone
    squatted it. The daemon logs `pipe \\.\pipe\saiife exists and is not
    ours; refusing to start` and exits 1. The service manager retries every
    second, and the hooks deny meanwhile.
  - **Client.** It opens the pipe with the impersonation level
    `SECURITY_IDENTIFICATION`, so the daemon may learn who the caller is
    but can never act as the caller. Then it reads the pipe's owner. An
    owner other than `<S>` (for the personal broker, the user's own SID) is
    `ClientError::Owner`, and no byte is sent. `ERROR_PIPE_BUSY` is retried
    every 10 ms until the deadline. The deadline covers each read and write.
    When it passes, the hook denies and exits.
  - **Server.** After `connect().await`, one synchronous call does
    `ImpersonateNamedPipeClient`, `OpenThreadToken(TOKEN_QUERY, OpenAsSelf =
    TRUE)`, `GetTokenInformation(TokenUser)`, `GetTokenInformation(TokenGroups)`,
    `GetTokenInformation(TokenIntegrityLevel)`,
    `GetTokenInformation(TokenRestrictedSids)`
    and `RevertToSelf`. There is no `.await` inside. It also reads
    `GetNamedPipeClientProcessId`, for attribution only. If `RevertToSelf`
    ever fails, the process aborts. It must never go on running as the
    client. A pipe peer counts as an elevated admin only at High integrity or
    above with no restricted SIDs: a low-integrity or restricted child of an
    elevated admin holds `Administrators` enabled, and is not uid 0.
  - **Why not AF_UNIX.** Windows supports AF_UNIX sockets but gives no peer
    credentials. `SIO_AF_UNIX_GETPEERPID` gives only a pid, and opening
    another user's process from a service account is denied, so a pid
    alone gives no SID.
- **uids (W12).** The policy, the audit and the IPC types keep `uid: u32`.
  On Windows the uid is `0` for SYSTEM and for a token with
  `BUILTIN\Administrators` enabled (an elevated admin, the Windows "root").
  Otherwise it is a stable 30-bit hash of the SID in
  `0x4000_0000..0x8000_0000`.
  - Audit records gain `"sid"`, the exact SID, so the hash is never the
    only identity on record (§8.5).
  - Policy names users as `name` or `DOMAIN\name`, resolved with
    `LookupAccountNameW`.
  - `group:<name>` means a local group. A peer is in it when its token's
    groups hold that group's SID. That also counts domain groups nested into
    the local group.
  - Two principals that hash to the same uid are a load error: `uid
    collision between <a> and <b>; rename one or tell the saiife
    maintainers`. In practice this does not happen.
  - The non-elevated token of an admin user gets that user's own hash, not
    0. This matches UAC: admin rights count only when elevated.
- **Gateway (W13).** The loopback TCP gateway is opt-in through
  `[gateway] tcp`, as on Linux, so D9's "No TCP by default" holds. There is
  no `gateway.sock`. `tcp_peer_refused` returns
  `None` on Windows, as on macOS. There are no gateway children, and the
  daemon's own uid cannot mint a token. `saiife api` and `saiife mcp` use
  the control pipe and need no gateway.
- **The co-signer's asker (W13, plan 21).** The Claude Code co-signer on
  `127.0.0.1:7433` must know who asks, and the HTTP request does not say.
  The service cannot open a token of the agent's user (its DACL has no entry
  for `NT SERVICE\saiifed`), and `SeDebugPrivilege` is refused. So:
  - `GetExtendedTcpTable(AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS)` gives the
    pid that owns the client end of the connection (`Asker::Process`).
  - The hook connection that bound the call (its pid from
    `GetNamedPipeClientProcessId`) must be a descendant of that pid, at most
    `ASKER_MAX_DEPTH = 3` parent steps (Claude Code, then Git Bash or
    PowerShell, then `saiife.exe`; 1 in exec form). One `Toolhelp32`
    snapshot per wait. Where the service may read them, a parent created
    after its child (a reused pid) and an asker in another session than the
    binder stop the walk. Otherwise `Waited::Foreign`, the `NoReport` deny.
  - The judged principal is that hook connection's SID and token groups.
  - Not a boundary against the same user: a process of the agent's user can
    start a child with Claude Code as its parent
    (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`) and bind from it. Against that
    code the barrier is the service's own judgment (§6.1.1), not the tie.
  - On Linux the asker is the uid of the client socket in `/proc/net/tcp`; on
    macOS the `so_uid` of `net.inet.tcp.pcblist_n`, a private layout parsed
    strictly by record length (an unknown size is no asker). No asker is a
    deny. `status.cosign.asker` is `"proc_net"`, `"pcblist"` or
    `"tcp_table"` when the lookup worked on a connection the daemon made to
    itself at startup, else null.
  - The `PeerCred.pid` of a pipe client still never grants access on its
    own; on Windows it now also ties a bind to the asker.
- **Personal broker (W25).**
  - The state dir is `%LOCALAPPDATA%\saiife\personal`.
  - The pipe is `\\.\pipe\saiife-user-<SID>`, owned by the user's SID, with
    a DACL for that SID only (ruling: SYSTEM needs no access to a user's
    broker). The client checks that the owner is its own SID.
  - The vault key is a Credential Manager generic credential. Target
    `saiife:vault-key`, persist `CRED_PERSIST_LOCAL_MACHINE` (never
    roaming), blob 32 bytes.
  - Autostart is the value `saiife-broker` under
    `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, set to
    `"<exe>" daemon --user` by `saiife daemon --user --autostart on`.
  - As on Linux, this mode has no boundary against the same user (§6.6, §7).
- **Install needs elevation (W26).** Install needs an elevated admin token
  (uid 0 by W12). From a non-elevated shell it refuses with `run this from
  an elevated terminal (Run as administrator)` and exit 2.

References: Microsoft Learn, "Named Pipe Security and Access Rights",
`ImpersonateNamedPipeClient`, `GetNamedPipeClientProcessId`, "Credentials
Management" (`CredWriteW`); devblogs.microsoft.com/commandline/af_unix-comes-to-windows;
docs.rs `tokio::net::windows::named_pipe::ServerOptions` and
`std::os::windows::fs::OpenOptionsExt`.

#### 5.3a.3 ACLs

Unix modes become SDDL. Each path has one expected security descriptor.
Install sets it, and `doctor` reads it back and compares. Every path that
install creates gets an owner and a protected DACL, so inheritance from
`C:\ProgramData` is cut. `<S>` is the service SID, `<A>` the SID of the
local group `saiife-audit`, and `RX = 0x1200a9` (read and execute).

| Path | SDDL |
|---|---|
| `C:\ProgramData\saiife` | `O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)(A;;0x1200a9;;;<S>)` |
| `…\bin`, `…\bin\saiife.exe`, `…\etc` and everything below `etc` | `O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1200a9;;;<S>)` |
| `…\state` and everything below it | `O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;<S>)` |
| `…\state\keys\vault.key` | `O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;<S>)` |
| `…\log` | `O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;<S>)(A;;0x1200a9;;;BU)` |
| `…\log\audit` and everything below it | `O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;<S>)(A;OICI;0x1200a9;;;<A>)` |
| `…\log\daemon` and everything below it | `O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;<S>)(A;OICI;FR;;;<A>)` |
| the managed files and every dir install creates for them | `O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)` |

- **Setting a descriptor propagates only to children that inherit.** `set_sddl`
  (`SetSecurityInfo` on an open handle, which is not a reparse point or a
  hard-linked file) reaches an existing child that inherits: CI read one back as
  `AI(A;ID;FA;;;LA)(A;ID;FA;;;SY)(A;ID;0x1200a9;;;BU)`, its old inherited entries
  plus the new Users entry. It does not reach a child with `P` set, nor an
  explicit entry a child holds. So a pre-existing tree (a protected child, or one
  an old ACL left user-writable by an explicit entry) is fixed only by setting
  each entry: install walks the tree
  top-down without following reparse points and sets every entry
  (`winacl::set_sddl_tree`), refusing a reparse point or a hard link. On a
  file, Windows drops `OI` and `CI`, so an `OICI` row reads back without them
  (`winacl::actual_file_ok`); a directory keeps them.
- **New dirs are created with their descriptor** (`CreateDirectoryW` with
  security attributes). So there is no moment where a user could add a file
  through the inherited `C:\ProgramData` ACL, which lets Users create
  entries.
- **Our own paths** must satisfy `protected_ok`. The owner is SYSTEM,
  Administrators or TrustedInstaller. There is no reparse point. The
  `writers` are a subset of SYSTEM, Administrators, TrustedInstaller, plus
  `<S>` where the table grants it. Inherit-only grants count here, since new
  children would get them; only `CREATOR OWNER` is exempt, as a placeholder.
- **Files the service creates.** On a row the service may write, a file or
  dir it created reads back with `<S>` as owner, its token's group, and the
  parent's ACEs marked inherited (`AI`, `ID`). So on those rows `<S>` may be
  the owner, and the comparison ignores the group and the inheritance flags.
  The grants must still be exactly the row's, so a file another account owns,
  or that Users or `<A>` can write, still fails. Every other row is compared
  exactly. To be confirmed on a real machine in `locked-windows`.
- **An existing path that fails `protected_ok`** is refused with exit 2
  naming the path. Examples: a `C:\ProgramData\saiife`,
  `C:\ProgramData\OpenAI` or `C:\ProgramData\gemini-cli` created by a user,
  and so owned by them. Install never takes over a dir someone else may
  still control.
- **The dirs an agent reads its policy from** (`ClaudeCode`,
  `managed-settings.d`, `OpenAI\Codex`, `gemini-cli`) must pass `protected_ok`
  even when an admin made them (ruling, plan 19b Task 7's review). A stock child
  of `C:\ProgramData` lets Users create entries, so a user could plant a settings
  file that install would merge and re-ACL, or that the agent would read. The
  refusal tells the admin to correct that dir's ACL. Only `C:\ProgramData\OpenAI`
  holds no policy, so it needs `ancestor_ok` alone, with a warning.
- **`--purge` keeps the root while a managed file still names the binary.** With
  the root gone any user could recreate `C:\ProgramData\saiife\bin\saiife.exe`,
  and a hook left behind would run it for every user. It warns instead. A plain
  uninstall warns that the hook stays, and that Claude then blocks every tool.
- **Ancestors** (`C:\`, `C:\ProgramData`, `C:\Program Files`) must satisfy
  `ancestor_ok`. The owner is SYSTEM, Administrators or TrustedInstaller
  (`C:\Program Files` is owned by TrustedInstaller by default). There is no
  reparse point. No
  non-admin allow ACE (not inherit-only) holds `WRITE_DAC`, `WRITE_OWNER`,
  `DELETE`, `FILE_DELETE_CHILD`, `GENERIC_WRITE` or `GENERIC_ALL`. Users may
  create new entries in `C:\ProgramData`. That is the default, and it is
  harmless, because they cannot rename or delete ours.
- **The vault key (W15)** is `state\keys\vault.key`. It is 32 random bytes
  written by install, mode `daemon_file`, never rotated, and readable only by
  `<S>` (plus SYSTEM and Administrators).
  - DPAPI is not used. Install runs as an admin, not as the virtual
    account, so it cannot seal a key for that account. A DPAPI key that the
    daemon makes at first start would be lost when the service profile is
    reset, and the vault with it.
  - On a running machine, the DACL is the barrier, as the file mode is on
    Linux. Disk encryption (BitLocker) protects backups and images.
    `doctor` does not probe it. It prints one Info line that points to the
    docs.

References: Microsoft Learn, "Security Descriptor String Format".

#### 5.3a.4 Approvals

Same-user approval is off on Windows (W16, owner ruling 2026-11-05), as on macOS.
Approvals need a second account. `same_user = "reauth"` acts as `"deny"`: a same-user
decision is refused with `reauth_unavailable` and the text `same-user approval is off on
Windows: approvals need a second account, from a separate session`. There is no prompt, no
cooldown and no password anywhere: not in `approval.decide`, not in the CLI, not in the
daemon. `LogonUserW` is not called. A requester can still withdraw its own request. Only
SYSTEM, an elevated admin and `[admin]` users can lift or narrow lockdown.

- **Why.** The agent runs as the human's user. As that user it can capture a console prompt
  (a global hook covers the whole desktop, and `AttachConsole` reads the input queue), read
  or inject into the CLI that holds the password, print a prompt of its own, or put another
  `saiife` first on the user's `PATH`. One capture is enough, and what it captures is the
  human's Windows password, which is good for far more than saiife. `CREDUIWIN_SECURE_PROMPT`
  doesn't help: the blob still returns to a process of the same user. Windows Hello doesn't
  either: the answer reaches only the CLI, and the daemon can't verify it.
- **The second account must approve from a separate session.** `runas /user:approver` on the
  agent's desktop can be captured by the same means, so it does not count.
  - OpenSSH is probably refused: W11's pipe DACL denies `NU` (network logons), and an SSH
    logon is probably a network logon. This is not verified.
  - Switching user and RDP should give a separate session. **Neither is verified.** The
    owner's VM checks them before the docs may recommend one.
- A later daemon-verified factor outside the agent's reach (a phone code, a hardware key
  signing a challenge built from the request) could bring same-user approval back. It is new
  design work and is not planned.

References: Microsoft Learn, "Hooks Overview", `AttachConsole`, `CredUIPromptForWindowsCredentialsW`.

#### 5.3a.5 Guard: shell dialects, paths and rules

This subsection applies in developer mode and in locked mode.

**Dialects (W4).** The guard knows three: `Posix`, `PowerShell` and `Cmd`.
The payload picks the dialect.

| Payload | Dialect |
|---|---|
| Claude Code `Bash` (on Windows it is Git Bash) | `Posix` |
| Claude Code `PowerShell`, on every OS | `PowerShell` |
| Codex `Bash` and Gemini `run_shell_command` on a Windows host | both `PowerShell` and `Posix`. The stricter verdict wins (deny > ask > allow; a rule hit beats no hit) |
| anything else on Linux and macOS | `Posix`, as today |

Codex and Gemini run commands through PowerShell on Windows. Gemini can be
pointed at `cmd.exe` through `ComSpec`, so the guard does not rely on it.

**What the PowerShell and cmd readers cover (W5).** They turn their command
text into the same `Segment`s the POSIX lexer makes. So every pack rule
applies and the engine is unchanged.

- Statements split on `;`, `|`, `&&`, `||` and newlines (cmd: `&`, `&&`,
  `||`, `|`). Quoting is read (`'…'`, `"…"`, backtick escapes; cmd `"…"` and
  `^`). Redirections are read (`>`, `>>`, `2>`, `*>`; cmd `>`, `>>`, `2>`).
  Words carry the same flags the POSIX lexer sets.
- External programs (`git`, `docker`, `kubectl`, `terraform`, `aws`, `az`,
  `gcloud`, `psql`, `mysql`, `mongosh`, `saiife`, …) pass through unchanged.
  A trailing `.exe` is dropped from argv[0], case-insensitive.
- A fixed table translates cmdlets, their aliases and cmd builtins to POSIX
  equivalents. Names are case-insensitive. PowerShell parameters match by
  unambiguous prefix (`-r`, `-rec`, `-Recurse`). Only the listed parameters
  are translated. Others pass through as written.

| PowerShell (aliases) / cmd | Becomes | Parameters translated |
|---|---|---|
| `Remove-Item` (`ri`, `rm`, `rmdir`, `del`, `erase`, `rd`); cmd `del`, `erase`, `rd`, `rmdir` | `rm` | `-Recurse`→`-r`, `-Force`→`-f`, `-Path`/`-LiteralPath`→operand; cmd `/s`→`-r`, `/q` and `/f`→`-f` |
| `Copy-Item` (`cp`, `copy`, `cpi`); cmd `copy`, `xcopy`, `robocopy` | `cp` | `-Recurse`→`-r`, `-Destination`→last operand |
| `Move-Item` (`mv`, `move`, `mi`), `Rename-Item` (`ren`, `rni`); cmd `move`, `ren` | `mv` | `-Destination`/`-NewName`→last operand |
| `Get-Content` (`gc`, `cat`, `type`); cmd `type` | `cat` | `-Path`/`-LiteralPath`→operand |
| `Set-Content` (`sc` in 5.1), `Add-Content` (`ac`), `Out-File`, `Clear-Content` (`clc`) | a `>` redirect to the path | `-Path`/`-FilePath`/`-LiteralPath`→target |
| `New-Item` (`ni`, `md`, `mkdir`) | `touch`, or `mkdir` with `-ItemType Directory` | `-Path`→operand |
| `Get-ChildItem` (`gci`, `ls`, `dir`); cmd `dir` | `ls` | `-Recurse`→`-R` |
| `Select-String` (`sls`); cmd `findstr` | `grep` | `-Path`→operand |
| `Set-Location` (`cd`, `sl`, `chdir`), `Push-Location` (`pushd`); cmd `cd`, `chdir`, `pushd` | `cd` | `-Path`→operand |
| `Stop-Process` (`kill`, `spps`); `taskkill` | `kill` | `-Id`/`/pid`→operand, `-Name`/`/im`→`-n <name>` |
| `Invoke-WebRequest` (`iwr`, `curl`, `wget` in 5.1), `Invoke-RestMethod` (`irm`) | `curl` | `-Uri`→operand, `-OutFile`→`-o`, `-InFile`→`--data-binary @` |
| `Start-Process` (`saps`, `start`); cmd `start` | argv `[FilePath, ArgumentList…]` | `-FilePath`, `-ArgumentList` |
| `$env:NAME = v`; cmd `set NAME=v` | an assignment word `NAME=v` | none |

- **Nested commands are judged inside,** as `sh -c` is today:
  `powershell` and `pwsh` with `-Command`/`-c` (the rest of the line),
  `-EncodedCommand`/`-enc`/`-e` (base64 of UTF-16LE, decoded, at most
  64 KiB decoded), `cmd /c` and `cmd /k`, `Invoke-Expression`/`iex` with
  one literal string, `Invoke-Command -ScriptBlock { … }`, `& { … }` and
  `. { … }`. A nested string whose dialect is known is read in that
  dialect.
- **What the readers cannot see** is marked like the POSIX lexer's
  unresolved substitution (`Word.has_substitution`), and **denied, in every
  mode**: the attacker chooses this syntax, so a recorded allow would be a
  bypass. (POSIX `eval "$x"` keeps its own outcome.) This covers `$var` and
  `$(…)` in a command position or an operand, `& $x`, `iex` of a non-literal,
  cmd `%VAR%` and `!VAR!`, an `-EncodedCommand` that does not decode, a
  here-string with expansions, and a broken payload whose tool is `PowerShell`.
  Under `Strictest` this holds for the PowerShell reading. A note from the POSIX
  or cmd reading there is recorded, and follows `Fail` below, because that
  grammar over text meant for another shell is noise (`%h%d`, a backtick).
  The same outcome holds for the `Bash` route on a Windows-style host (owner's
  ruling, plan 19a review): a nested `powershell`, `pwsh` or `cmd` the reader cannot
  read denies, and so does a shell with no command to read, because it runs its
  stdin (`echo x | cmd`, `cat f | bash`), and `wsl` with an unknown option. `wsl CMD`
  is a nested POSIX line. On Linux and macOS this route stays as it was: `pwsh -c`
  from the `Bash` tool is not read inside.
- **Budget and panic follow `Fail`,** in every dialect: `error_allowed` in
  developer mode, `error_denied` in locked. A failed stdin read in developer mode
  stays open. Out of budget, what is left of the line still gets the rules and
  lexical paths, and a line that denies there is a deny; one no rule denies stays
  a recorded allow in developer mode.
- **A shell line over the size limit (256 KiB) is denied in every mode** (owner's
  ruling), `error_denied`, with a message telling the agent to split it, on any
  OS. Padding must not be a way past the guard. File tools are not affected, and
  a broken or unreadable stdin stays as it is.
- **Limits, written down** (as `cd` tracking is for POSIX in §10):
  aliases and functions defined in the same command (`Set-Alias`,
  `function f {…}`), `.ps1` script contents, .NET calls
  (`[IO.File]::Delete(…)`), COM objects, and the registry provider beyond
  the `core.lock` rules below.

**Windows paths (W6).** The function is pure and lives in `saiife-guard`.
On a Windows host, each path operand is canonicalized before the path rules
run.

- Both `\` and `/` separate. The result uses `/`, with the drive letter
  lower-cased (`c:/…`). Case is folded for matching, because NTFS is
  case-insensitive by default.
- `\\?\C:\…` and `\\.\C:\…` become `c:/…`. `\\?\UNC\host\share` and
  `\\host\share` stay UNC. `\\localhost\c$\…`, `\\127.0.0.1\c$\…` and
  `\\?\UNC\localhost\c$\…` become `c:/…`.
- Git Bash `/c/Users/…` and `/cygdrive/c/…` become `c:/Users/…`.
- Each component loses its trailing dots and spaces, because Win32 strips
  them (`.env.` opens `.env`). An alternate data stream suffix (`:stream`,
  `::$DATA`, `:$DATA`) is dropped, so `.env::$DATA` is `.env`.
- `~`, `$HOME`, `$env:USERPROFILE`, `${env:USERPROFILE}` and
  `%USERPROFILE%` all mean the profile dir. `$env:LOCALAPPDATA` and
  `%LOCALAPPDATA%`, `$env:APPDATA` and `%APPDATA%`, `$env:TEMP` and `%TEMP%`
  are known variables (`PathVars`).
- When the path exists, `std::fs::canonicalize` resolves 8.3 short names
  (`PROGRA~1`), junctions and symlinks, as on unix. A path that does not
  exist keeps its lexical form.
- Pack globs written with `~/` match profile paths on Windows. A rule
  written for `/etc/...` never matches a Windows path. Windows targets get
  their own rules.

**Windows hook budget.** D10's 50 ms does not hold on the `windows-latest` runner:
process start alone is 20.3 ms, `saiife --version` 26.9 ms, and the developer hook
84.7 ms median and 90.4 ms p95. With no code change, runner noise has since moved that
p95 from 83-87 ms to 102-114 ms. By the owner's ruling the Windows CI budget is 130 ms
p95, which allows for slow runners; Linux and macOS keep theirs. The planned speed-up
should tighten it, with no figure promised.

**New pack rules (W7).** Amended by the owner's ruling on the hook budget (plan 19a
Task 10, +1 ms against `main`): compiling these rules on every OS cost about 5 ms
per hook call. So every rule in the table below carries `platform = "windows"`, and
its triggers are in `windows_triggers`. They exist on a Windows-style host only: a
Windows build of saiife, whichever dialect a line is read in, Git Bash included.
Linux and macOS never compile them, and WSL is Linux. `"windows"` is the only value
of the marker. Any other fails the pack's load, like an unknown key.

The shipped packs skip a rule for another OS unread. Any other load
(`load_pack_str`, `load_pack_for`, `load_packs_dir`) compiles and checks it, then
leaves it out with a warning that names it, so a marker cannot hide a deny or a
broken rule without saying so. saiife loads only its built-in packs today, so no
user pack is in force at runtime; those functions are what a later user-pack feature
has to go through. A policy's `[guard] ask` may name a rule of any OS, on any OS.

Deviation from the plan's text: the rules have no `[[example]]` lines,
because packs have no such mechanism (`[[example]]` belongs to policies, §8.1).
The examples are the deny and allow cases in `crates/guard/tests/corpus_windows.rs`
and `corpus_windows_round1.rs`, end to end under the shipped packs.

`windows-root-rm` reads a Windows host's `rm` operands as W6 names them
(`c:/Windows`, `~` for the profile), so it holds no spellings of its own.

What remains different on Linux and macOS from before this plan, on purpose, is one
rule: `core.process/kill-saiife-name` has no marker. It denies `kill` of a wildcard
that can match saiife, or of every process, wherever the word stands and however it
is reached: `kill s*`, `kill *`, `kill "*"`, `kill 12 13 ?`, `kill -s TERM s*`, `sudo
kill s*`, `sh -c 'kill *'`. The PowerShell tool
runs there too, and `Stop-Process -Name sai*` arrives as that `kill` and really
stops the process. It costs a hook nothing, since `core.process` compiles only on a
line that names `kill`. Everything else, `rm -rf /mnt/c/Windows`, `rm -r c:/` and the
names of Windows programs included, gets the verdict it had before this plan.

A word on a PowerShell provider drive names no file, so it is judged by what is
done to it: `HKCU:`, `HKLM:` and `Cert:` read freely, but for `HKLM:\SAM` and
`HKLM:\SECURITY`. `Env:` reads one variable freely (`Get-Item Env:X`, as `printenv
X`), but a read of the whole drive or a wildcard on it (`dir env:`, `gc env:*`) is
denied, as `env` is, by the owner's ruling in the plan 19a review. `HKCU:` writes pass
but for `Environment`;
`HKLM:` and `Cert:` writes are denied; `Env:` writes are denied for `SAIIFE_*`.
Any other drive is denied, as is a provider path in a file tool. `name:rest`
without a slash is a drive only for a name PowerShell gives a provider
(`HKLM:x`, not `test:unit` or `nginx:latest`), and `x::y` only with `Registry::`
and a hive, `Environment::` or `Certificate::`.

The budget (D10) is no way past these: when it runs out on a Windows host, or on
a line a PowerShell or cmd reader read, the rest of the line still gets the rules
and the path rules, symlinks and globs included, for a fixed count of system calls;
past it the line is denied. Only a deny comes of that; otherwise the answer stays
the timeout. A POSIX line on Linux or macOS keeps its order and its record.

Windows-style hosts only:

| Pack | Rules |
|---|---|
| `core.filesystem` | recursive `rm` on `c:/`, `c:/windows`, `c:/program files`, `c:/program files (x86)`, `c:/programdata`, `c:/users` or `~`, for any drive letter; `format <drive>:`, `Format-Volume`, `Clear-Disk`, `Remove-Partition`, `Initialize-Disk`, `diskpart`, `cipher /w`, `vssadmin delete shadows`, `wbadmin delete`; `bcdedit /delete` and `/set`; `reg delete` of a hive root |
| `core.secrets` | `cmdkey /list`, `vaultcmd /list…`, `reg save` and `reg export` of `HKLM\SAM`, `HKLM\SECURITY` or `HKLM\SYSTEM`. The existing `~/.ssh`, `~/.aws` and `.env` path rules already cover the profile through W6 |
| `core.self` | writes and deletes under `%LOCALAPPDATA%/saiife` (the developer data dir), of the running `saiife.exe`, and of the project hook files; moving the data or audit dir for later programs (`setx`, `reg add …\Environment`, `Set-ItemProperty`, `[Environment]::SetEnvironmentVariable`, `Set-Item Env:`) |
| `core.process` | `kill`, `taskkill` (with `/fi` filters that name it or that name no process) and `Stop-Process` of `saiife`; `wmic process … terminate`; `Get-Process \| Stop-Process` |
| `core.lock` (locked mode) | writes, deletes, `icacls`, `takeown` and `Set-Acl` under `c:/programdata/saiife`, `c:/program files/claudecode`, `c:/programdata/openai/codex` and `c:/programdata/gemini-cli`; `sc` or `sc.exe` with `stop`, `config`, `delete`, `failure` or `sdset` on `saiifed`; `Stop-Service`, `Set-Service` and `Remove-Service` on `saiifed`; `net stop saiifed`; `reg add` and `reg delete`, and `Set-ItemProperty`, `Remove-ItemProperty` and `New-ItemProperty`, on `HKLM\SOFTWARE\Policies\ClaudeCode`; deleting a parent key of it or of the service key; recursive or inherited ACL changes on a parent of those folders; `net localgroup saiife-audit … /add` and `/delete`. Listing ACLs (`icacls PATH` with only `/t /c /l /q`) is allowed |

**Project hooks (W8).** The project hook command stays `saiife check
--hook-exit --agent <a>` through `PATH`. It works in Git Bash, PowerShell
and cmd. Claude Code's project matcher gains `PowerShell` on every OS:
`MATCHER = "Bash|PowerShell|Read|Grep|Glob|LS|Write|Edit|MultiEdit|NotebookEdit"`.
The previous value becomes `MATCHER_V2`. A project hooked with it, or with
`MATCHER_V1`, is upgraded in place, as plan 2's matcher is today. Claude
Code's docs say to match `Bash|PowerShell` in hooks that inspect shell
commands. `saiife status` warns `hook matcher predates the PowerShell tool;
run saiife init to update` for an old project.

Agent facts used here: the Claude Code PowerShell tool has the tool name
`PowerShell` and reads `tool_input.command`. It is on by default on Windows
for claude.ai and Console accounts (`CLAUDE_CODE_USE_POWERSHELL_TOOL`).
Gemini CLI on Windows runs `powershell.exe -NoProfile -Command`.

References: code.claude.com/docs/en/tools ("PowerShell tool");
geminicli.com/docs/tools/shell/; code.claude.com/docs/en/settings.

#### 5.3a.6 Packaging, signing and the FFI boundary

**The FFI boundary (W1).**

- A new crate, `crates/win` (`saiife-win`), is the second crate allowed to
  use `unsafe`, after `saiife-darwin`. It mirrors `saiife-darwin`.
- `unsafe` may appear only in `crates/win/src/ffi/*.rs`, and only under
  `cfg(windows)`. The crate root has
  `#![cfg_attr(not(windows), forbid(unsafe_code))]` and
  `#![deny(unsafe_op_in_unsafe_fn, clippy::undocumented_unsafe_blocks)]`.
  Every `unsafe` block has a `SAFETY:` comment. Every handle and every
  `LocalFree`, `NetApiBufferFree` or `CredFree` buffer is owned by a small
  RAII guard.
- The FFI dependency is `windows-sys = "=0.61.2"`, a target dependency under
  `cfg(windows)` only.
- Why our own crate: no safe crate covers named-pipe client identity, SDDL
  ACLs and local group lookups together. Two needs have safe
  crates, and those are used instead of FFI: `windows-service` (the service
  manager) and `winreg` (registry reads). `std` covers the pipe client open
  (`OpenOptionsExt::security_qos_flags`), reparse-point checks
  (`MetadataExt::file_attributes`) and `fs::canonicalize`. `rpassword` reads a
  console value without echo, for `secret add` and `connect` only. Approvals
  never ask for a password (W16).
- `scripts/check-unsafe.sh` allows `unsafe` in `crates/darwin/` and in
  `crates/win/src/ffi/`, and nowhere else. `unsafe` that a dependency's macro
  expands into is not caught.
- In 19a, `saiife-win` has pure modules only: SID math and an SDDL reader.
  The FFI module arrives in 19b.

**The complete list of FFI calls.** No other call may be added without
updating this list and this section.

| Area (file) | Calls |
|---|---|
| Security descriptors (`sd.rs`) | `ConvertStringSecurityDescriptorToSecurityDescriptorW`, `ConvertSecurityDescriptorToStringSecurityDescriptorW`, `GetSecurityDescriptorOwner`, `GetSecurityDescriptorDacl`, `LocalFree` |
| File ACLs (`acl.rs`) | `GetSecurityInfo`, `SetSecurityInfo` (each on a handle opened with `FILE_FLAG_OPEN_REPARSE_POINT` and checked, so a final reparse point swapped in cannot redirect them), `GetFileInformationByHandle` (on the same handle before `SetSecurityInfo`: a non-directory with `nNumberOfLinks != 1` is refused, so a hard link cannot redirect a set to its target), `GetFinalPathNameByHandleW` (on the same handle before `SetSecurityInfo`: the path Windows opened must be the path asked for, so a junction swapped in higher up cannot redirect a set), `CreateDirectoryW` (with a descriptor) |
| SIDs, accounts, local groups (`account.rs`) | `ConvertSidToStringSidW`, `ConvertStringSidToSidW`, `LookupAccountNameW`, `LookupAccountSidW`, `NetUserGetLocalGroups`, `NetLocalGroupGetMembers`, `NetApiBufferFree` |
| Tokens (`token.rs`) | `GetCurrentProcess`, `OpenProcessToken`, `GetCurrentThread`, `OpenThreadToken`, `GetTokenInformation` (`TokenUser`, `TokenGroups`, `TokenIntegrityLevel`, `TokenRestrictedSids`), `CloseHandle` |
| Pipes (`pipe.rs`) | `ServerOptions::create_with_security_attributes_raw` (an `unsafe fn` of tokio), `GetNamedPipeClientProcessId`, `ImpersonateNamedPipeClient`, `RevertToSelf`, `GetSecurityInfo` (the pipe owner, client side) |
| Process list (`proc.rs`) | `CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW`; plan 21: `OpenProcess` (`PROCESS_QUERY_LIMITED_INFORMATION`), `GetProcessTimes`, `ProcessIdToSessionId`: the creation time and session of a process where the service may read them, so the co-signer's process-tree tie rejects a reused parent pid and another session |
| Signature check (`trust.rs`) | `WinVerifyTrust` |
| Personal broker keychain (`cred.rs`) | `CredReadW`, `CredWriteW`, `CredDeleteW`, `CredFree` |
| Process setup and disk (`process.rs`) | `SetDefaultDllDirectories`, `SetStdHandle`, `GetDiskFreeSpaceExW` |
| Worker job (`job.rs`) | `CreateJobObjectW`, `SetInformationJobObject` (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`), `AssignProcessToJobObject`: the managed hook's eval worker dies with the hook |
| Sockets (`net.rs`, plans 20 and 21) | `setsockopt` (`SO_EXCLUSIVEADDRUSE`): the Claude Code co-signer's listener takes `127.0.0.1:7433` for itself before it binds; `GetExtendedTcpTable` (`AF_INET`, `TCP_TABLE_OWNER_PID_CONNECTIONS`, no privilege): the pid that owns a co-sign client's socket, which must be an ancestor of the hook that bound the call |
| Service entry (`service.rs`) | the `extern "system"` entry that `windows_service::define_windows_service!` expands to. Its expansion contains `unsafe`, so the macro may be used only here |

That is 46 functions and one macro (`GetSecurityInfo` is listed twice), all in `crates/win/src/ffi/`: 45 `windows-sys` calls and the tokio call. The tokio call needs the crate feature
`pipe-server`, which only `saiife-daemon` enables. So `saiife-win` stays
tokio-free on the hook path.

**The MSI (W20).**

- It is built with WiX Toolset v5.0.2 (MS-RL). WiX v6 and later carry the
  Open Source Maintenance Fee for projects that earn revenue. That is an
  owner decision for later.
- It is per machine, one MSI per architecture (`x64`, `arm64`). A fixed
  `UpgradeCode` is generated once and never changed. `MajorUpgrade` is
  scheduled `afterInstallExecute`.
- It mirrors plan 18 decision 1. The package owns only
  `C:\Program Files\saiife\saiife.exe` (the package binary), its docs and one
  system `PATH` entry for that dir. A deferred custom action, run as SYSTEM,
  does `"[INSTALLFOLDER]saiife.exe" system install --fleet --package`.
- `--package` maps exit 1 (installed, with doctor warnings or failures) to
  0, so the MSI succeeds. It writes the doctor text to
  `C:\ProgramData\saiife\log\install.log`. Exit 2 fails and rolls back.
- On removal (`REMOVE="ALL"` and not `UPGRADINGPRODUCTCODE`), a deferred
  action runs `system uninstall` before the files go. Plan 18's removal
  warning goes to the MSI log and `install.log`.
- Rollback actions undo both, so the machine is never unlocked while the
  MSI says saiife is installed, nor locked with no product to remove it by.
  A first install that fails after its files are in runs `system uninstall`
  (not when `installed.toml` was there before the MSI ran: that locked mode
  is kept). A failed upgrade runs `system install --fleet --package` with the
  old staging copy, which the rollback has put back. A failed removal runs
  `system install --fleet --package` again. `SAIIFE_FORCE_FAIL=1` on the
  msiexec line forces a failure after the install action and after the file
  removal, for the package test.
- The fleet files are `C:\ProgramData\saiife\etc\fleet\config.toml` and
  `install.toml` (plan 18 formats). The deployment tool writes them before
  the MSI runs.

**Signing (W21).** One signing step signs both `saiife.exe` builds and then
both MSIs, on tag pushes only. `signtool verify /pa` runs after each.
Unsigned builds still pass CI.

- Since mid-2023, CA rules require code-signing keys to live in hardware.
  So a `.pfx` in a GitHub secret is not an option for a new certificate.
  Azure Artifact Signing (Microsoft's managed service) keeps the key in
  Microsoft's HSM.
- EV certificates no longer give instant SmartScreen reputation. A new
  signed release builds reputation as it is downloaded. MSIs pushed by
  Intune or GPO are not checked by SmartScreen.
- Developer mode ships signed zips and `install.ps1` (plan 19a).

**Fleet recipes (W22).**

- **Intune Win32 app.** The MSI is wrapped with `IntuneWinAppUtil.exe`.
  Install is `msiexec /i saiife-<v>-<arch>.msi /qn /l*v C:\ProgramData\saiife\log\msi.log`.
  Uninstall is `msiexec /x {ProductCode} /qn`. Install behavior is System.
  The detection script `detect.ps1` writes to STDOUT and exits 0 only when
  the service is running and `saiife.exe doctor --json` exits 0 or 1. A
  platform script, `fleet-files.ps1`, is a dependency. Custom compliance
  uses `discovery.ps1` and `rules.json`, with `saiife_installed` (Boolean)
  and `saiife_doctor_exit` (Int64), as in plan 18's Linux recipe.
- **GPO.** Assign the MSI under Computer Configuration → Software
  Installation, from a share readable by Domain Computers. Put the fleet
  files there with Group Policy Preferences → Files. This is docs only.

**CI `locked-windows` (W23).** The matrix is `windows-2022` and
`windows-2025`, both x64. GitHub's Windows runners run as an administrator
with UAC disabled, so the job is elevated. ARM64 is built and signed in the
release, but its locked flow is owner handwork until a `windows-11-arm`
cell is added. The scripts are PowerShell 7 (`pwsh`).

**Binary hardening (W28), the A4 analogue (§9.2).**

- Release and CI builds link the CRT statically and set
  `/DEPENDENTLOADFLAG:0x800`, so load-time DLLs come only from System32. The
  daemon and the CLI call `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`
  first thing in `main`.
- `binary::inspect_pe` refuses a debug build, a binary without the flag, and
  imports outside the allowlist. It warns on a missing Authenticode
  signature.
- Windows has no `LD_PRELOAD`. DLL planting in the cwd or on `PATH` is the
  attack, and the `locked-windows` job tests it.

References: Microsoft Learn, "Code signing options for Windows app
developers", Azure Artifact Signing quickstart, "Win32 app management in
Microsoft Intune"; github.com/Azure/artifact-signing-action;
docs.firegiant.com/wix/osmf/; docs.rs `windows-service` 0.8.1.

#### 5.3a.7 Linux-only or different on Windows

| Feature | On Windows |
|---|---|
| Session attribution (W17) | process names only |
| MCP gateway (W18) | refused |
| `run --secret` and `run --cloud` (W19) | work, with a Windows trust check |
| Claude Code managed settings (W24) | `HKLM` policy wins over files |
| Agent users who can become admin (W27) | `doctor` fails |

- **Session attribution (W17).** `CreateToolhelp32Snapshot` gives each pid's
  parent and exe name for every user, with no rights needed. It gives no
  start time, so pid reuse cannot be detected. `ProcStat.start_time` is 0,
  and `cmdline` is `None` (as on macOS). This is attribution only. Nothing
  is allowed because of it. `node.exe` ancestors get `session = null`.
- **The MCP gateway is refused (W18).** `[mcp.<name>]` is a load error with
  `MCP_NEEDS_LINUX`, as on macOS. Windows has no Landlock analogue that
  saiife uses. AppContainer or a job object sandbox is a follow-up.
  `saiife mcp` (connector tools) works.
- **`run --secret` and `run --cloud` (W19).**
  - A `run_allow` entry must be an absolute `X:\…\name.exe` path on a local
    fixed drive. UNC paths and relative paths are load errors.
  - The file and the folder that holds it must pass `protected_ok` with
    writers limited to SYSTEM, Administrators and TrustedInstaller. A stock
    `C:\ProgramData` is not enough for that folder: Users could drop a DLL
    beside the exe. Every ancestor above it must pass `ancestor_ok`. There may
    be no reparse point anywhere in the chain. This check runs where the Linux
    `root_owned_chain` check runs.
  - The list of refused interpreters also holds `py`, `pyw`, `wsl`, `dotnet`,
    `msiexec`, `conhost`, `wmic` and `javaw`. These count only for a `.exe` or
    on Windows, so `run_allow` on Linux and macOS means what it did.
  - The loader-variable scrub gains `COR_ENABLE_PROFILING`, `COR_PROFILER`,
    `COR_PROFILER_PATH`, `COR_PROFILER_PATH_32`, `COR_PROFILER_PATH_64`,
    `CORECLR_ENABLE_PROFILING`, `CORECLR_PROFILER`, `CORECLR_PROFILER_PATH*`,
    `DOTNET_STARTUP_HOOKS` and `__COMPAT_LAYER`, on every platform. They
    are harmless elsewhere.
- **Claude Code's HKLM policy wins over files (W24).** If
  `HKLM\SOFTWARE\Policies\ClaudeCode` has a `Settings` value with a policy
  key, Claude Code uses that source and skips `managed-settings.json` and
  `managed-settings.d/` by default.
  - Install and `doctor` read it with `winreg`. With a `Settings` value
    present and no `"managedSourcesBehavior": "merge"` in it,
    `agents.claude.policy` **fails**: `HKLM\SOFTWARE\Policies\ClaudeCode sets
    Claude Code's managed settings, so saiife's drop-in is ignored; add
    "managedSourcesBehavior": "merge" there, or put saiife's hooks in it`.
    Install exits 1 with the same line.
  - The user-writable HKCU key is never consulted by Claude Code when an
    admin source exists, so it is not checked.
- **Agent users that can become admin (W27).** An agent user in
  `Administrators`, `Backup Operators`, `Server Operators`, `Hyper-V
  Administrators` or `Account Operators` is a `doctor` **fail**. Each is
  root-equivalent. By default, UAC elevates an admin with a consent click
  and no password (`ConsentPromptBehaviorAdmin = 5`). It drops to a
  **warning** only for `Administrators`, and only when
  `ConsentPromptBehaviorAdmin = 1` (credentials on the secure desktop) and
  `PromptOnSecureDesktop = 1`: `agent user <u> is an administrator:
  elevation needs its password`.
- **Also Linux-only for now:** the egress recipe (§6.20), and `syslog` to a
  local socket (use a udp, tcp or tls target).

References: code.claude.com/docs/en/managed-settings ("How Claude Code
combines managed sources"); docs.github.com "About GitHub-hosted runners".

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

**Note (plan 19b, W27): Windows.** An agent user in Administrators, Backup
Operators, Server Operators, Hyper-V Administrators or Account Operators is a
`doctor` fail, matched by the groups' well-known SIDs, since their names are
localized. It drops to a warning only for Administrators with
`ConsentPromptBehaviorAdmin = 1` and `PromptOnSecureDesktop = 1`. `doctor` reads the
service, the descriptors of §5.3a.3 and the binary instead of the Unix modes, and it
names the Linux checks with no Windows form yet (plaintext credentials, model logins,
leftover project hooks, hard links in the tree, the members of `saiife-audit`).

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
- **Claude Code co-signer (plan 20):** a second `PreToolUse` hook, of type
  `http`, posts the same hook input to the daemon at
  `http://127.0.0.1:7433/v1/cosign/claude` (`timeout: 10`,
  `onFailure: "block"`, no `headers`). The drop-in also lists
  `http://127.0.0.1:7433/*` in `allowedHttpHookUrls`; the lists merge across
  settings files, so a user's own list cannot skip it. Claude Code runs both
  hooks in parallel and takes the strictest answer
  (`deny` > `defer` > `ask` > `allow`). The daemon keys the call by `HookKey { agent, session,
  tool_use_id, input_sha256 }`, where `input_sha256` is the SHA-256 of
  `tool_input` in a canonical JSON form (keys sorted at every level,
  compact), and waits up to 8 s from the request's arrival (`COSIGN_WAIT`)
  for the command hook's verdict on that key:
  - a recorded `allow` (or `approved`): `200` with an empty body, which is no
    opinion, so the command hook's verdict and Claude Code's own permission
    prompts stand. The co-signer never answers `allow`;
  - anything else: `200` with the deny body
    `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"saiife: BLOCKED (fail closed): <reason>"}}`.
    `<reason>` is one of: `no saiife hook reported a verdict for this call`
    (nothing by 8 s), `the saiife hook ended without a verdict`, `saiife
    denied this call`, `the call has no session or tool use id`, `the payload
    is too large` (over 16 MiB, `MAX_BODY`), `the payload is not JSON`, and
    since plan 21 `the saiife service's own judgment denies this call: <reason>`
    (`Rejudged`, the guard reason cut to 200 characters), `the saiife service
    could not judge this call` (`RejudgeFailed`) and `the saiife service could
    not tell who sent this call` (`AskerUnknown`).
  Only `POST /v1/cosign/claude` is served (else `404`). A request with an
  `Origin` header gets `403`, a `Content-Type` other than `application/json`
  gets `415`. A request over the in-flight caps (8 per uid, or per pid on
  Windows, and 16 in all) waits for a slot, its asker's share first, before
  its body is read, and gets `503` only when none is free within
  `COSIGN_WAIT` from its arrival (since the re-judge concurrency review,
  2026-11-10: ten or more parallel sessions of one user burst past 8). Each of these
  blocks only the request it answers, through `onFailure`. Every deny except
  `saiife denied this call` writes a `hook` record with `event:
  "cosign_denied"`, at most one per reason per 10 s, the next one carrying
  `suppressed: <n>`. The co-signer has no token: its answer can only take
  away. It binds in system mode only, on Linux, macOS and Windows (on Windows
  with `SO_EXCLUSIVEADDRUSE`). If the port is taken, the daemon keeps
  running, writes a `daemon` record with `event: "cosign_bind_failed"`,
  `status` shows `"cosign": {"addr": null, "error": "<error>"}`, `doctor`
  fails `cosign.listen`, and Claude Code blocks every call through
  `onFailure`. The port is fixed (owner ruling 2026-11-09). Codex and Gemini
  CLI have no co-signer; they get detection only (below).
- **The co-signer re-judges (plan 21).** Both must agree: the empty `200`
  needs the hook's recorded allow **and** the service's own judgment of the
  request body, the exact input Claude Code sent. Neither can allow alone,
  and the service's judgment cannot widen what the hook denied. It runs on
  Linux, macOS and Windows, one code path (owner ruling 2026-11-09).
  - **Lexical.** The service judges with `FsView::Lexical`: the guard makes
    no file system call, so the service never reads the agent user's files.
    Paths are judged as written. It does not see what only the agent user's
    view decides: a symlink, a junction, a glob's matches, a directory's
    contents, and the project config's extra packs (A18 note). That is
    accepted: code of that user can change each of them after any judgment
    (A21), so they were never a boundary against it. The hook still judges
    them and denies on its own. A move or copy target is judged both as
    itself and as `target/name`, because the lexical view cannot tell a
    folder from a file, and `-t`/`--target-directory` names a folder. One
    corpus case is stricter than the hook, by owner ruling (`KNOWN_STRICTER`):
    `cp review.md .claude`.
  - **As whom.** The principal is the asker (Linux, macOS: the socket's uid)
    or, on Windows, the SID and groups of the hook connection that bound the
    key, tied to the asker (§5.3a.2, W13). The path variables (`HOME`,
    `XDG_CONFIG_HOME`, the agent config dirs) come from that principal's
    account record, never from an environment the agent set. The packs are
    the system policy's for that principal's scope, with no project config.
    For an MCP tool the system `[guard.mcp] allow` list applies; the pin
    check stays the hook's.
  - **Approvals.** A call that only `[guard] ask` rules deny (`askable`)
    passes when the same hook connection consumed a grant
    (`grant.consume`) whose `raw_sha256` equals the SHA-256 of the command
    in the body. Any other grant, or none, is `Rejudged`.
  - **The pool.** `saiife __eval --serve` workers, children of the service,
    running as the service account (never root, never the agent user), with
    a cleared environment; on Windows in a kill-on-close job. They read
    length-prefixed `EvalRequest` frames (u32 big-endian, at most
    `MAX_EVAL_BYTES`). Fixed values: `REJUDGE_POOL = 4` warm workers;
    `REJUDGE_MAX_USES = 500` requests each, then replaced;
    `REJUDGE_TIMEOUT = 3 s` per request, always inside `COSIGN_WAIT` from
    arrival; `REJUDGE_PER_PRINCIPAL = 3` requests of one principal judged at
    once, so one user never holds every worker and parallel sessions of one
    user are not judged one at a time (2 and 1 before 2026-11-10: a burst of
    8 calls waited 32 ms at p95, 10 ms with 4 and 3); `REJUDGE_MAX_WAITING = 32`
    requests waiting in all (at least the co-signer's 16 in flight, so it
    never refuses a request the co-signer let in), and one more fails at
    once, before its request is built. A request whose co-signed HTTP request is gone (answered, timed
    out, or its connection closed) is cancelled: the pool checks before it
    builds the worker's request and while it waits for a worker, and gives
    up its place at once. The blocking work holds the HTTP request's
    in-flight slots until it ends, so it never exceeds the co-signer's caps. A worker that
    crashes, hangs or answers badly is killed and replaced, and its request
    fails. The daemon calls the pool on `spawn_blocking`.
  - **Decision.** `wait` gives `Allow` and the re-judge allows: empty `200`.
    The re-judge denies an askable call with the matching grant: empty `200`.
    Any other re-judge deny: `Rejudged` and a `rejudge_denied` record. The
    re-judge fails or passes its deadline: `RejudgeFailed` and a
    `rejudge_failed` record. `wait` gives anything else (`Deny`,
    `NoVerdict`, `Timeout`, `Foreign`): plan 20's answer, and no re-judge
    is started. On every system the re-judge starts only once `wait` gives
    `Allow`, as the binder's principal (on Windows only then is the SID
    known), so a loop of calls the hook denied takes no place in the pool.
  - **No judge.** A system daemon without a pool denies every co-signed call
    with `RejudgeFailed`, and `status.cosign.rejudge.error` says why.
  - **Status.** `cosign.rejudge: {"workers": <n>, "error": <s|null>}`,
    `cosign.asker: "proc_net" | "pcblist" | "tcp_table" | null`,
    `hooks_rejudge_denied: {since_start, last_ts}`.
  - **Not closed:** the squat of `127.0.0.1:7433` while the service restarts
    (a squatter answers an empty `200`, and a forged hook exit 0 then
    allows; it needs the service to crash first, A5; owner ruling
    2026-11-09), and injection into Claude Code itself (A21).
- **Hello first (plan 20):** `check --managed` connects to the daemon and
  sends `hook.begin {agent, event}` before it reads its input, and
  `hook.bind` with the call's `HookKey` once it has. The `audit.append` on
  that connection is the verdict. A begun connection that ends without a
  verdict, or that runs 10 s past `hook.begin` (`HOOK_OVERRUN`, after which
  the daemon closes it), becomes a `hook` record with decision `no_verdict`,
  unless another connection for the same key delivers the verdict within 5 s
  (`RECONNECT_GRACE`, the approval step's reconnect). This holds for every
  agent. It is a record and a `doctor` warning (`hooks.no-verdict`), with no
  automatic lockdown (owner ruling 2026-11-06). A hook killed before it read
  its input has no key (`bound: false`); the co-signer then cannot match it
  and denies at its 8 s cap.
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
load /etc/saiife/config.toml (on Windows the pipe is fixed)
  fails to load                               → deny, error_denied (no socket to register with)
connect to saiife.sock, send hook.begin {agent, event}   (plan 20: before stdin is read)
read stdin (no size cap for path fields, as v1; a shell payload over 1 MiB → deny, error_denied)
load policy.d + project .saiife/config.toml (add-only merge, §8.2)
if lockdown == "all"                         → deny, record
spawn worker: /opt/saiife/bin/saiife __eval  (payload on a pipe; worker has the 50 ms budget)
  while it runs: hook.bind {HookKey}           (a payload that gives no key: no bind, nothing else changes)
  worker crash / signal / no answer in 3 s    → deny, error_denied
if decision == ask (proposed, §6.10.4)       → grant.consume or approval.create → allow or deny
  connection lost (approval timed out)        → new connection: hook.begin, hook.bind (same key)
build Record v2 (masked)                      → audit.append on the same connection (the verdict)
  no ack in 2 s, or daemon refuses           → deny, error_denied (record left with the client: stderr only)
answer the agent: exit 0 silent (allow) | exit 2 + stderr reason (deny)
```

A begun connection that ends with no `audit.append` is the daemon's
`no_verdict` record (§6.1.1, §8.5).

The worker costs a fork and exec (about 2–5 ms). It turns an abort or a
stack overflow in the engine, which v1 cannot catch, into a clean
`error_denied`. The latency target is p95 under 40 ms per hook call on the
bench machine (v1 is about 16 ms).

**Note (plan 21): speed.** Measured in CI, the managed hook cost about 90 ms
p95 on Linux and 104-139 ms on Windows, and 62-66 ms of that was building the
engine (TOML parse and regex compile) on every call. Two changes:

- **Claude Code judges in-process** (owner ruling 2026-11-09, option B): no
  `__eval` worker. The judgment runs on a thread of the hook (8 MiB stack),
  after the key is bound, with the environment a worker would get. A hang
  denies at `WORKER_TIMEOUT` and a panic is caught, both as `error_denied`. A
  crash kills the hook, which `onFailure: "block"` blocks, the co-signer
  denies, and the daemon records as `no_verdict`. Codex and Gemini CLI keep
  the worker, because for them a crashed hook can let the call run (§9.3).
- **Prebuilt packs** (option C): `build.rs` turns the built-in `packs/*.toml`
  into static Rust data, so no hook parses that TOML, and each rule regex and
  pack prefilter compiles when a command first reaches it, off the engine's
  budget. Building the engine went from 30-54 ms to 0.3-1.3 ms, and a whole
  judgment from 38-66 ms to 6.5-19 ms (`ci-locked` build); verdicts are the
  same on 207,360 repo-line cases. Packs from `policy.d` still compile at
  load.

The managed hook benches were report-only during plan 21 and gate CI again
with budgets per OS set from plan 21's CI measurements (§13): the managed
bash call's p95 was 41.2 to 50.0 ms on Linux (`ubuntu-24.04`, budget 60 ms),
under 40 ms on macOS (budget 40 ms), and 59.1 ms on `windows-2022` and
59.6 ms on `windows-2025` (budget 130 ms; about 150 ms before plan 21).
Exec form in the drop-in (option E, no Git Bash or PowerShell per Windows
call) waits until the Claude Code version that added `args` is known.

#### 6.1.3 Lockability per agent

| Agent | Managed location | Can the user switch the managed hook off? | Fail closed on saiife error | v2 status |
|---|---|---|---|---|
| Claude Code | `managed-settings.d/50-saiife.json` | No, managed outranks all (confirm for `disableAllHooks` in plan 7) | Yes (`onFailure: "block"`, ≥ 2.1.295). Plan 20: the co-signer HTTP hook on `127.0.0.1:7433` denies a call the command hook did not record as allowed, so a hook killed with a forged exit 0 is denied too. Plan 21: the co-signer also judges the call itself, so a forged allow of a denied call is denied | **lockable** |
| Codex | `requirements.toml` | No, `[features] hooks = true` pin; managed hooks skip trust review | Only for errors saiife reports (exit 2 + stderr). Timeout, crash or missing binary fail open in Codex. Plan 20: no co-signer; a hook that ends without a verdict is recorded (`no_verdict`) | **lockable, fail-open gaps listed** |
| Gemini CLI | system `settings.json` | No by settings, but `GEMINI_CLI_SYSTEM_SETTINGS_PATH` lets a **new** Gemini process skip the system file | Exit 2 blocks; a timeout fails open. Plan 20: no co-signer; a hook that ends without a verdict is recorded (`no_verdict`) | **lockable with caveats** if it passes the plan 7 checks, otherwise "not lockable" (decision 9) |

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

**Note (plan 17).** `system install` writes the Claude Code managed MCP
allowlist drop-in `/etc/claude-code/managed-settings.d/60-saiife-mcp.json`
from policy (the `saiife` server by command, plus each
`[guard.mcp] allow_servers` by name). This replaces the `--mcp-allow <list>`
flag (plan 17 decision 14): the list is derived from policy, so the two
cannot disagree. Codex and Gemini get no managed MCP keys yet; `doctor` says
their MCP servers are restricted by the hook only.

### 6.2 Daemon (`saiifed`)

- **Start:** loads policy (an invalid policy at start means "deny all
  connector calls, accept audit", recorded as `daemon`/`policy_invalid`),
  opens the audit chain (verifies the last 1 000 records and the last
  checkpoint), rebuilds rate-limit counters from the connector records of the
  last 24 h, binds both sockets, then tells systemd it is ready.
- **Reload** (SIGHUP or `policy reload`): parses, validates and swaps the
  policy in one step. An invalid new policy is refused, the old one stays,
  and a `policy` record with `result = "rejected"` is written. A call takes
  the policy in force when it starts. If a reload brings any policy change
  (any edit to the config or a connector manifest, whichever call it touches)
  while the call waits for an upstream slot, it is denied with
  `policy_changed`: nothing is sent and nothing counts against limits. The
  same holds for a lockdown (§6.18). A call already sent finishes.
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
clients that cannot use Unix sockets. On Windows it is the only gateway
listener (§5.3a.2, W13). It requires a bearer token from
`saiife api token` (bound to the uid, valid for 12 h, stored hashed by the
daemon).

**Note (plan 13).** `LOCAL_PEERPID` gives the pid of the socket's last
user, not strictly the connecting process, so on macOS nothing is granted
on a pid; `LOCAL_PEERCRED`'s uid, taken at connect, is what counts.
**`[gateway] tcp` on macOS** (decision 8): without `/proc` the daemon cannot
find a TCP peer's uid, so the own-uid check on the TCP listener is skipped
(`tcp_peer_refused` returns `None`). That is safe because macOS has no
gateway children (§6.15) and the daemon's own uid cannot mint the bearer
token: the control socket refuses own-uid peers in locked mode. The token
is still required.

**Note (plan 19b, W11, W13): Windows.** The control endpoint is the pipe
`\\.\pipe\saiife`, with the same frames. The caller's identity is its token's SID
and groups, read by the daemon while it impersonates at identification level; the
pid (`GetNamedPipeClientProcessId`) is attribution only. A client with no security
quality of service keeps its real identity, so it cannot pose as someone else. The
pipe has at most 254 instances. CI confirmed that the daemon, as `NT
SERVICE\saiifed`, reads another user's SID from a client's token. There is no
`gateway.sock`; the loopback TCP listener is opt-in and needs the bearer token, and
`tcp_peer_refused` returns `None`, as on macOS. The 401 matrix, the token expiry and
the `peer.tcp` record run on Windows in `windows_daemon.rs`.

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
  per secret. Built (plan 13, decision 9): `saiife daemon --user` runs on
  macOS with the key in the login Keychain (`MacKeychain`). Without
  `XDG_RUNTIME_DIR` the runtime dir is `~/Library/Caches/saiife` (0700,
  created if missing) with the sockets in `run/`; a purge of the caches
  needs a broker restart. A socket path over 103 bytes is refused with a
  clear line. Built (plan 19b, W25): on Windows the key is a Credential Manager
  generic credential (`saiife:vault-key`, `CRED_PERSIST_LOCAL_MACHINE`), the state is
  under `%LOCALAPPDATA%\saiife\personal`, and the endpoint is the pipe
  `\\.\pipe\saiife-user-<SID>`, owned by and open to that SID only. The broker runs
  only as a person's account: a local or domain account (`S-1-5-21-…`) or a
  Microsoft Entra ID account (`S-1-12-1-…`); virtual accounts, AppContainers and
  groups are refused.
- **Locked mode on Windows (plan 19b, W15):** the vault key is
  `C:\ProgramData\saiife\state\keys\vault.key`, readable by the service SID, SYSTEM
  and Administrators only (§5.3a.3). DPAPI is not used.
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
   the same host, at most 3. Timeout 30 s by default. After each wait for a
   slot of the service's pool, a call is denied and not sent if lockdown came
   on (`lockdown`) or any policy changed (a reload, §6.2: `policy_changed`).
   A 401 is not refreshed or sent again in that case: it is the answer, the
   call stays allowed because it was sent, and the record says
   `auth_retry_skipped`.
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
- `saiife run --secret` refuses an oauth2 secret (`run_not_allowed`): it is
  for connectors only, and its refresh token never leaves the daemon.
- New mask shapes for the wave 2 and 3 services: Stripe `sk_`/`rk_` and
  `whsec_`, Slack `xox*-`, `xoxe`, `xapp-` and webhook URLs, Discord bot
  tokens and webhook URLs, Linear, Sentry, GitLab `gl*-`, Salesforce session
  ids, Intercom, Airtable `pat…` and WooCommerce `ck_`/`cs_`. A webhook URL
  keeps its host path and masks the rest; a token glued to other text is
  masked too.
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

**Note (plan 13).** On macOS the match uses process names only (decision
6): `KERN_PROCARGS2` (the command line) is readable only for one's own uid,
so a `node` ancestor never matches an agent, and Gemini CLI under `node`
gets `session = null` (the stricter shared bucket). The peer pid comes
from `LOCAL_PEERPID` (the socket's last pid); a pid that is gone or was
reused gives no session, never another one. Attribution only: nothing is
allowed because of it.

**Note (plan 19b, W17): Windows.** The walk uses `CreateToolhelp32Snapshot`, which
gives each pid's parent and exe name for every user. It gives no start time
(`start_time` is 0) and no command line, so pid reuse cannot be detected and a
`node.exe` ancestor gets `session = null`, as on macOS. Attribution only.

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
- **Note (plan 13): same-user approval is off on macOS.** Plan 13 changed
  the flow (decisions 3–5): the daemon, not the CLI, acquires the right.
  The CLI makes an empty authorization reference and sends its external
  form as `auth` in `approval.decide`; the daemon runs
  `/usr/bin/security authorize -u -i -d com.saiife.approve` with that form
  on stdin, `PATH` only and a 120 s timeout, as it runs `pkcheck` on Linux.
  `-60005`/`-60006` are denied, `-60007` (no GUI, SSH) is unavailable,
  anything else is an error. The right is written with
  `security authorizationdb write`: `class = user`,
  `authenticate-user = true`, `session-owner = true`, `shared = false`,
  `timeout = 0`, `allow-root = false`. This is built and tested but **not
  used**: the prompt shows only the right's fixed `default-prompt`, never
  the request, so a same-user agent could start an approval of its own
  request while the human believes they confirm another one (polkit shows
  the daemon's `--detail`; nothing on macOS lets the daemon set the prompt
  without FFI). So on macOS `same_user = "reauth"` acts as `"deny"`: a
  same-user decision is refused with `reauth_unavailable` and
  "re-authentication unavailable: approvals need a second account", with no
  prompt and no cooldown, and `doctor` reports "same-user approval is off
  on macOS: approvals need a second account". Approvals need a second
  account, and only root and `[admin]` users can lift lockdown. Install
  still registers the right. Spec departure, for the owner to confirm; the
  follow-up is a daemon-side prompt that carries the request (a small
  audited FFI in `saiife-darwin`, owner decision).
- **Note (plan 19b, W16): same-user approval is off on Windows.** See §5.3a.4.
  `same_user = "reauth"` acts as `"deny"`, with no password handling at all. The
  second account must approve from a separate session; `runas` on the agent's
  desktop can be captured. Built as designed (owner ruling 2026-11-05): there is no
  `LogonUserW` call and no password re-authentication. Approver names and `[[scope]]
  users` match by the account's SID, and a `group:` approver counts by the token's
  groups only, never by a name lookup that would count a deny-only Administrators
  entry. CI ran an approval with a third account (`approver-hook`).
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
- Environment names match `[a-z0-9_-]{1,64}` and may not be `base` (approvals show the base config as "env base").
- A malformed `env` value is a bad request in locked mode too; it never falls
  back to another environment.
- `env use --scope` is root only (the spec's "admin rights").
- In developer and personal-broker mode an environment changes connector
  calls only; its guard packs apply in locked mode. A developer-mode `policy
  show` prints a line saying it does not reflect the project env.
- A well-formed project `env` that no environment defines falls back to the
  base config with a warning in developer and personal-broker mode; locked
  mode ignores the project `env`.
- `status` and `policy show` print each environment's policy hash beside the
  base one (`policy show`: a non-admin sees only their own environment's).
- The managed hook applies the scope environment. It looks up the caller's
  groups only when some scope binds an `env`: `/etc/group` when the user is
  local and `nsswitch.conf` takes groups from `files` alone, else NSS. A
  failed lookup is a recorded `error_denied` with policy `unavailable`.
  `env list` and the daemon's `policy.show` treat a failed group lookup as
  an error, never as "no environment", and the daemon does not cache a
  failed lookup.
- An approved request is sent under the environment it was asked under or
  not at all (`send_failed`, `env_changed`): in locked mode the scope's
  environment at send must be the stored one, in developer mode the stored
  one must still be defined. A request stored with no environment is not
  checked. Approvers see the environment in `approvals show`, the list and
  the notification summary.
- `env --system-config <file>` means locked mode, as plan 16's flag does
  everywhere: a file without `locked = true` is refused.
- In personal-broker mode the HTTP gateway socket uses the base config, not
  the project env: only `saiife api` sends the project's `env`, so agents
  should use it. Binding an environment to an `api.token` is a later item.

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

> Note (plan 15): STS mode is AWS only for now. GCP and Azure cannot scope a
> token down in general, so `mode = "sts"` on those connectors is a config
> error; they stay in sign mode until they have a way to scope tokens. Owner
> to confirm.

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

**Note (plan 13).** `run --secret` and `run --cloud` work on macOS
(decision 10). `DYLD_*` is removed from the command's environment with the
other loader variables (`LD_*`), and refused as a `--secret` variable name,
on every platform, because it is harmless on Linux. `/etc`, `/var` and
`/tmp` are symlinks into `/private` on macOS, and a link in `run_allow`
never grants its target, so on macOS an entry through one is a load error
with a hint: "run_allow entry /var/x goes through the /var symlink on
macOS; write /private/var/x instead". The root-owned-chain checks accept
exactly those three root-owned links to `private/<same name>`.

**Note (plan 19b, W19): Windows.** Built as §5.3a.7 says: a `run_allow` entry is an
absolute `X:\…\name.exe` on a local fixed drive; the file and its folder must pass
`protected_ok` with writers limited to SYSTEM, Administrators and TrustedInstaller,
every ancestor `ancestor_ok`, with no reparse point in the chain; the refused
interpreters gain `py`, `pyw`, `wsl`, `dotnet`, `msiexec`, `conhost`, `wmic` and
`javaw`; and the loader scrub gains the .NET profiler variables,
`DOTNET_STARTUP_HOOKS` and `__COMPAT_LAYER`, on every platform. The value reaches
the client over the control pipe.

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

**Note (plan 17).** The gateway runs in locked mode only (decision 12): in
personal broker mode its servers would run as the user, so `[mcp.*]` there
is a load error. Children are confined with Landlock (files and exec) and
`no_new_privs`; **their network is not sandboxed**, so a hostile server can
still send out what it was given. The daemon refuses socket peers that are
gateway children and, in locked mode, any peer with the daemon's own uid.
`via` in a record is declared by the client and is attribution only. A call
waiting for a child's slot follows the same rule as a connector call (§6.7.1,
step 9): a slot not had in time is the `concurrency` limit, a server that is
not running is `upstream_unavailable`, and neither counts. See `docs/mcp.md`.

**Note (plan 13).** The gateway stays Linux only in v2.1 (decision 7): it
needs Landlock, and `sandbox-exec` is deprecated, so it is not used. On
macOS `[mcp.<name>]` is a load error in every mode ("the MCP gateway needs
Linux (Landlock) in this version"), the same mechanism as the personal
broker refusal above. `saiife mcp` (the connector tools) works on macOS.
The follow-up is a macOS sandbox for gateway children (Endpoint Security
or a separate uid).

**Note (plan 19b, W18): Windows.** The gateway is refused on Windows too, with the
same `MCP_NEEDS_LINUX` load error; `doctor` prints `mcp.landlock` as Info. `saiife
mcp` works over the control pipe, with the connector tools. Claude Code's managed MCP
allowlist (`60-saiife-mcp.json`) pins `C:/ProgramData/saiife/bin/saiife.exe mcp`. An
AppContainer or job-object sandbox for gateway children is a follow-up.

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

Checks added by plan 20 (both values come from the one `status` call doctor
already makes):

- **`cosign.listen`:** fail when Claude Code is installed and
  `status.cosign.addr` is null: "the co-signer is not listening on
  127.0.0.1:7433 (<error>), so Claude Code blocks every call". Pass with the
  address. Info when Claude Code is not installed.
- **`hooks.no-verdict`:** warn when `status.hooks_no_verdict.since_start` is
  above 0: "<n> hook call(s) ended without a verdict since the daemon started
  (last <ts>): a hook was killed, crashed or timed out; see saiife audit
  --kind hook". Pass at 0. The count starts again when the daemon restarts;
  the records stay in the audit.
- **`files.binary` on Linux:** a mode other than `0711` warns
  "/opt/saiife/bin/saiife is <mode>, expected 0711; run saiife system
  install". Run as a user other than root, a read that fails with `EACCES` is
  info: the binary is not readable by that user, which is the point. macOS
  keeps `0755` and is not checked for mode.
- **`agents.claude.policy`** also fails when the installed drop-in lacks the
  co-signer hook or its `allowedHttpHookUrls` entry: "the Claude Code drop-in
  has no saiife co-signer hook; run saiife system install".
- **Proxy:** a warning when a proxy variable (`HTTPS_PROXY`, `HTTP_PROXY`) is
  set for Claude Code and `NO_PROXY` does not include `127.0.0.1`. Claude
  Code may send the co-sign request to the proxy, which blocks every call.
  saiife does not set `NO_PROXY` in managed settings: an `env` value there
  would replace the user's and the admin's own entries (owner ruling
  2026-11-09).

Checks added by plan 21 (on every system install with Claude Code; all values
come from the same `status` call):

- **`cosign.rejudge`:** pass "the service judges each Claude Code call itself
  (<n> workers)"; fail "the service cannot judge Claude Code calls (<error>),
  so every call is blocked".
- **`cosign.asker`:** pass with the source (`proc_net`, `pcblist` or
  `tcp_table`); fail "the co-signer cannot tell who asks (<platform reason>),
  so every Claude Code call is blocked".
- **`hooks.rejudge-denied`:** warn when `status.hooks_rejudge_denied.since_start`
  is above 0: "<n> call(s) the hook allowed were denied by the service's own
  judgment (last <ts>): a forged verdict, or a guard difference; see saiife
  audit --kind hook".
- **`locked.preview` on Windows** names only the installed agents without a
  co-signer: "Windows locked mode is a preview for Codex and Gemini CLI: a
  process of the agent's user can end their hook with exit 0". With only
  Claude Code installed and `cosign.listen`, `cosign.rejudge`,
  `cosign.asker` and `agents.claude.policy` all passing, and an
  `agent-version` check that showed Claude Code at least the minimum (none
  failing), it passes: "Windows locked mode for Claude Code: each call is
  judged by the hook and by the service". A whole co-signer that Claude Code
  never calls (an HKLM override, a drop-in without the HTTP hook, an old
  Claude Code) does not pass it. If any of these fails, it stays info with the
  old text; when only the version was not checked, the old text says to run
  `doctor --user <name>` as that user. An elevated `doctor` therefore can
  never drop "preview": it does not run `claude.exe`, so it cannot show the
  version. The agent user runs `saiife doctor --user <name>` from its own
  shell. Linux and macOS have no `locked.preview`.

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
| `saiife system install [--config <file>] [--agents claude,codex,gemini] [--approvers <list>] [--non-interactive]` | root | Create users and groups, install the binary to `/opt/saiife/bin`, write `/etc/saiife` (from `--config` or a commented default), the unit or plist, and the managed hooks for the chosen agents; start the daemon; write `installed.toml`; run `doctor`. Idempotent. `--fleet` reads `/etc/saiife/fleet/config.toml` and `install.toml` (plan 18). |
| `saiife system uninstall [--keep-audit]` | root | Remove exactly what `installed.toml` lists. The audit and vault are kept unless `--purge`. |
| `saiife daemon --system \| --user` | service manager | Run the daemon. `--user` is personal broker mode (`$XDG_RUNTIME_DIR/saiife/`), after v2.0. Built (plan 16): Linux. Built (plan 13): macOS too; without `XDG_RUNTIME_DIR` the sockets are in `~/Library/Caches/saiife/run/` (§6.6). |
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

**Note (plan 19b, W25, W26): Windows.** "root" in this table is an elevated
Administrators token (or SYSTEM); `system install` and `uninstall` refuse from a
terminal that is not elevated (exit 2). `system install` there creates the service
`saiifed`, the local group `saiife-audit` and the tree of §5.3a.1; `--package` is for
the MSI's custom actions. `saiife daemon --user --autostart on|off` sets or removes
the `HKCU\…\Run` value `saiife-broker`; `--print-unit` is refused on Windows. `secret
add` and `connect` read a value without echo with `rpassword`; no approval command asks
for a password.

## 8. Config and data formats

### 8.1 `/etc/saiife/config.toml`

```toml
version = 2
locked = true                    # v1 reserved this key (v1 §5.1); true = locked mode

[daemon]
user = "saiife"                  # "_saiife" on macOS
socket_dir = "/run/saiife"       # "/var/db/saiife-run" on macOS (plan 13); fixed in locked mode

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
                     "timeout": 10, "onFailure": "block" },
                   { "type": "http",
                     "url": "http://127.0.0.1:7433/v1/cosign/claude",
                     "timeout": 10, "onFailure": "block" } ] }
    ],
    "ConfigChange": [
      { "hooks": [ { "type": "command",
                     "command": "/opt/saiife/bin/saiife check --managed --hook-exit --agent claude --event config-change",
                     "timeout": 10, "onFailure": "block" } ] }
    ]
  },
  "allowedHttpHookUrls": ["http://127.0.0.1:7433/*"],
  "disableAllHooks": false
}
```

The `http` hook is the co-signer (§6.1.1, plan 20). `allowedHttpHookUrls`
lists its URL so that a user's or project's own list, which merges with this
one, cannot skip it. The HTTP hook sends no `headers`, so
`httpHookAllowedEnvVars` does not affect it. On Windows the file differs in
the command path only (W9). `ConfigChange` has no co-signer: managed settings
outrank whatever it lets through. A test checks that this block equals the
file saiife writes.

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
`/`, with one exception.

> Note (plan 15): object keys may contain `/`, through two parameter types.
> `objectkey` (S3, Azure Blob) keeps `/` and percent-encodes each segment; it
> may only be the last path segment and is reachable by proxy as the path's
> tail. `objectname` (Cloud Storage) encodes the whole value, so `/` becomes
> `%2F`, and is named-only. Both refuse an empty value, more than 1024 bytes,
> a control character, `\`, an empty segment, and a `.` or `..` segment.
> Every other path parameter still may not hold `/`. Owner to confirm.

### 8.5 Audit record v2

Common fields (all kinds):

| Field | Type | Notes |
|---|---|---|
| `v` | int | `2` |
| `seq` | int | chain position |
| `prev` | hex | SHA-256 of the previous line's bytes |
| `ts` | string | UTC, ms, as v1 |
| `kind` | string | `guard`, `connector`, `approval`, `secret`, `policy`, `daemon`, `forward`, `notify`, `lockdown`, `checkpoint`, `key_rotate`, `genesis`, `hook` (plan 20) |
| `host` | hex | host id (§6.4.1) |
| `uid`, `user` | int, string | from peer credentials (daemon-written) or the process (developer mode) |
| `mode` | string | `developer`, `personal`, `locked` |
| `policy` | string | `sha256:<hex>` of the effective policy |
| `agent`, `project`, `tool`, `input`, `decision`, `saiife` | as v1 | **always present** so 0.1.0 readers can show every record; for non-guard kinds `tool` is the kind and `input` is a short masked summary |
| `session`, `pack`, `rule`, `reason` | as v1 | optional |
| `peer` | object | `{ "pid": 4242, "comm": "saiife" }`, attribution only |
| `permission_mode` | string | optional, the agent's permission mode from the hook payload (shows unattended runs) |

`decision` values: v1's `allow`, `deny`, `error_allowed`, plus `error_denied`,
`ask`, `approved`, `rejected`, `expired`, and `no_verdict` (plan 20). 0.1.0
readers keep unknown values (`DecisionKind::Unknown`).

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

**Note (plan 19b, W12): `sid`.** On Windows every daemon-written record also
carries `"sid"`, the caller's exact SID (`"S-1-5-21-…-1003"`), next to `uid`, which
there is only a label: 0 for SYSTEM and an elevated admin, else a 30-bit hash of the
SID (§5.3a.2). An approval record names the approver's SID the same way. Linux and
macOS records have no `sid`; readers that do not know it ignore it.

**Note (plan 20): the `hook` kind.** The daemon writes it from its own
knowledge of the hook connections (§6.1.1). Two events:

- `event: "no_verdict"`, decision `no_verdict`: a hook that began
  (`hook.begin`) and ended without an `audit.append`, after the reconnect
  grace. `agent` from `hook.begin`; `uid`, `user` (and `sid` on Windows)
  from the peer; `session` from the bound key; `tool` is `""` (the hook does
  not send it); `project` and `input` are `""`; there is no `policy`; `reason`
  is "the hook ended without a verdict (killed, crashed or timed out)".
  Extra fields: `bound` (whether `hook.bind` came), `tool_use_id` and
  `input_sha256` (null when unbound), `elapsed_ms` (from `hook.begin` to the
  end), `pid` (the peer's, attribution only), `hook_event` (the `event` of
  `hook.begin`, when it sent one) and `overrun: true` when the daemon closed
  the connection at `HOOK_OVERRUN`. These records are not folded.
- `event: "cosign_denied"`, decision `error_denied`: a co-signer deny other
  than `saiife denied this call` (the guard record already says why).
  `agent: "claude"`, `tool` from `tool_name`, `input` the command or path the
  guard would show (masked), `session`, `reason` the deny reason, and extra
  `tool_use_id` (masked and capped; no hash of the input). `session` and
  `input` are kept only when the asker's uid is known (Linux, macOS). On
  Windows the asker is a pid (W13): the record carries `asker_pid`, and folds
  per pid (plan 21). At most one per reason per 10 s; the next one carries
  `suppressed: <n>`.

**Note (plan 21): two more `hook` events**, from the co-signer's own judgment
(§6.1.1). One record per call (owner ruling 2026-11-09), with one safety
valve: past `REJUDGE_RECORDS_PER_MINUTE = 60` `rejudge_denied` records of
one principal in a 60-second window (from that principal's first record),
the window's other calls fold into one record, written when the window
ends: the last of those calls, with `suppressed` = how many calls it stands
for, itself included. So the audit volume's floor is not the only limit on
a flood of forged allows. `status.hooks_rejudge_denied` still counts every
call. `rejudge_failed` records fold like `cosign_denied` ones.

- `event: "rejudge_denied"`, decision `deny`: the hook recorded an allow and
  the service's own judgment denied the call. `agent: "claude"`, the
  principal's `uid` (and `sid` on Windows), `tool`, `input` (masked by
  `Record::new`), `session` (capped as above), and `pack`, `rule` and
  `reason` from the service's judgment. Extra fields: `hook_pid`,
  `tool_use_id` (masked and capped). `status.hooks_rejudge_denied` counts
  them, and `doctor` warns (`hooks.rejudge-denied`).
- `event: "rejudge_failed"`, decision `error_denied`: the service could not
  judge the call (no pool, a worker crash, a timeout, a bad answer). Same
  fields, without `pack` and `rule`.

A co-signed call that `wait` already denies (`Deny`, `NoVerdict`, `Timeout`,
`Foreign`) gets plan 20's answer and record, never one of these.

```json
{"v":2,"seq":2210,"prev":"41ab…","ts":"…","kind":"hook","host":"5ab1…","uid":1001,"user":"agent-shop",
 "mode":"locked","agent":"claude","project":"","session":"c-1","tool":"","input":"",
 "decision":"no_verdict","reason":"the hook ended without a verdict (killed, crashed or timed out)",
 "event":"no_verdict","bound":true,"tool_use_id":"toolu_02","input_sha256":"9c1e…","elapsed_ms":5214,
 "pid":4242,"hook_event":"PreToolUse","saiife":"0.2.0"}
```

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

**Note (plan 17).** A third type, `"type":"mcp"`, is a gateway tool call:
`service` is `mcp:<name>`, `operation` is the tool, and the display holds the
masked canonical arguments (cut at 4 KiB; a cut display needs
`--accept-truncated`). Identical pending requests share one id when nothing
in them was masked. On approval the current policy and the server's tool list
are checked again.

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
| A4 | Inject code into the hook (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`) | Linux binary is static musl (ignores `LD_PRELOAD`). macOS (v2.1) binary uses the hardened runtime (ignores `DYLD_*`). A running session's environment cannot be changed by a script. Windows (v2.2, W28): no `LD_PRELOAD`; the attack is a planted DLL. Release builds link the CRT statically, set `/DEPENDENTLOADFLAG:0x800` and call `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`; `inspect_pe` refuses a build without them. `locked-windows` planted DLLs beside a copy of `saiife.exe`: none loaded. |
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
| A18 | Edit the project config to drop packs or allow services | Project config is add-only in locked mode (§8.2). `core.self` still blocks the write. Note (plan 21): the co-signer's own judgment (§6.1.1) does not read the project config. Because the project only adds packs and `ask` and `deny` rules, a judgment without it allows a superset of the hook's, never less; the project's extra packs are the hook's check alone. |
| A19 | Use an MCP server with its own token | v2.0: tools of MCP servers not listed in `[guard.mcp] allow_servers` are denied. Listed servers are an admin-accepted, unbrokered gap: their calls are hooked and audited, and `status` and `doctor` warn about them (decision 10). After v2.0, the MCP gateway (proposed) moves their tokens into the vault. |
| A24 | Use the agent's own model-provider login (read it, or call the provider directly) | **Not prevented, by design** (owner decision 5). `core.secrets` still blocks the obvious reads of the login files (v1). The answer for companies that need it is a local model. |
| A20 | Read the response of a request with secrets in it | The response is masked for vault values and v1 patterns before it leaves the daemon. |
| A21 | Run its own code outside the hook (script, patched agent, nested agent with other settings) | **Not prevented in v2.** That code runs as the user with no keys, cannot touch saiife, and is not audited. v3. `doctor` warns when agent binaries are user-writable. A hook such code kills is recorded (`no_verdict`, plan 20). Such code can also swap a symlink, a junction or a folder's files, or edit its own project config, after any judgment; this is why the co-signer's lexical judgment (plan 21, §6.1.1) loses nothing by not seeing them. A verdict it forges for Claude Code is checked against the service's own judgment (A25). |
| A22 | Send data it can read to any host | **Not prevented in v2.** v3 egress control. Egress recipe (proposed, §6.20) for dedicated accounts on Linux. |
| A23 | Plant persistence that runs later outside a session (cron, user units, login items) | `core.lock` denies the common ways (proposed). A script can still do it: that code is as in A21. |
| A25 | Forge the hook's verdict on Windows: end the hook with `TerminateProcess(hook, 0)`, or begin, bind and append an allow itself | A process of the agent's user can still end the hook with exit 0 (it has full access to its own processes), or begin, bind and append an allow itself, with no code injection, and then end the real hook. Code injected into the hook can do the same. **Claude Code (plans 20 and 21):** the service judges every call itself, on the input Claude Code sent, and the co-signer (§6.1.1) answers "no opinion" only when both the hook's recorded verdict and the service's own judgment allow. A killed hook recorded nothing, so the call is denied ("the saiife hook ended without a verdict"). A forged allow of a call the policy denies is denied ("the saiife service's own judgment denies this call"), with a `rejudge_denied` record and a `doctor` warning (`hooks.rejudge-denied`). `locked-windows` asserts both on `windows-2022` and `windows-2025` with Claude Code's request simulated (`phase_forge`, §13), and both were denied in CI run 42673682022, so Claude Code on Windows is not a preview. **Left:** a forged allow of a call the policy allows runs, as it would anyway (pinned by a test). What only the user's own file system view decides is the hook's alone: a junction, a symlink, a glob's matches, the project's extra packs (A18 note). Code of the user can change these after any judgment (A21). **Codex and Gemini CLI:** recorded only (`no_verdict`, `doctor` warns `hooks.no-verdict`), no automatic lockdown, and still a preview: they have no HTTP hook, so no co-signer. **Not prevented:** a squat of `127.0.0.1:7433` while the service restarts (the daemon binds with `SO_EXCLUSIVEADDRUSE`, a failed bind is recorded and fails `doctor`): a squatter answers an empty `200`, and a forged hook exit 0 then allows. It needs the service to crash first (A5). Accepted for dropping "preview" for Claude Code (owner ruling 2026-11-09). Before plan 20 the call ran and no record was written (measured on both runners: the audit's size did not change). On Linux the binary is `0711`, so the hook cannot be traced by its own user, and a kill cannot choose an exit code; on macOS the hardened runtime refuses `task_for_pid` and the binary stays `0755`. There a forged allow already gained nothing, so the re-judge is defence in depth. In CI a second account could end the hook too, but only because both test accounts were started with `CreateProcessWithLogonW` from one runner session and so carry its logon SID (`S-1-5-5-0-…`), which the hook's default DACL grants: a test artifact, not a cross-user hole. |

### 9.3 Fail-closed matrix

| Failure | Claude Code | Codex | Gemini CLI |
|---|---|---|---|
| saiife reports an error (exit 2 + reason) | blocked | blocked | blocked |
| guard engine crash | blocked (plan 21: judged in the hook; a crash ends it, `onFailure` blocks, the co-signer denies, recorded `no_verdict`) | blocked (worker isolates it; parent denies) | blocked (same) |
| `check` parent killed or crashes | blocked (`onFailure`) | **runs**; recorded | blocked if exit code is not 0 or 1 (unverified for signals); recorded |
| hook timeout (10 s) | blocked | **runs** | **runs** |
| daemon down or not answering in 2 s | blocked (saiife denies) | blocked | blocked |
| binary missing | cannot happen to a locked install (root-owned); blocked by `onFailure` anyway | **runs** | possibly blocked (exit 127, unverified) |
| `check` ended with exit 0 by a process of the agent's user (Windows, A25; A21 class) | blocked (co-signer) | **runs**; recorded | **runs**; recorded |
| a forged allow by a process of the agent's user (A25) | **blocked (service judgment)** | **runs; recorded** | **runs; recorded** |
| co-signer not listening (`127.0.0.1:7433` taken, or the daemon down) | blocked (`onFailure`) | n/a | n/a |
| the service cannot judge the call (no pool, worker crash, timeout) | blocked (co-signer, `rejudge_failed`) | n/a | n/a |

The forged-allow row holds for a call the policy denies; a forged allow of a
call the policy allows runs, as it would anyway (A25). saiife answers well inside the timeout (an internal deadline of 3 s), so the
"runs" cells need the parent process itself to die or hang. These are the
fail-open gaps listed per agent in the docs and in `doctor`. "Recorded"
(plan 20) means the daemon writes a `hook` record with decision
`no_verdict` and `doctor` warns (`hooks.no-verdict`); the call still runs.

### 9.4 How much a record proves

- **Connector, approval, secret, policy, daemon, hook and checkpoint records**
  are written by the daemon from its own knowledge. They are authoritative.
  A `hook` record (plan 20) proves that a hook connection ended without a
  verdict; it cannot say why. A co-sign `rejudge_denied` record (plan 21) is
  the daemon's own judgment of the input Claude Code sent, not a claim of
  the hook: the hook had recorded an allow, and the service denied. It
  cannot say whether the hook's allow was forged or the two judgments
  differ (the lexical view is stricter, as for `cp review.md .claude`).
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
containers). Windows is in the Developer column until v2.2 (§5.3a); from v2.2 its
locked columns are a preview for Codex and Gemini CLI, and hold against mistakes and
helpful bypasses but not against A25 (§9.2). For Claude Code the service's own
judgment holds against A25 too: `phase_forge` (§13) was green on `windows-2022`
and `windows-2025` (CI run 42673682022), so Claude Code is not a preview there. The Personal broker column describes the mode that ships after
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
   install. Packages (`.deb`, `.rpm`; macOS `.pkg` after plan 13) run
   `system install --fleet`; see docs/fleet.md.

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

**Note (plan 19b, W23): Windows jobs.** All Windows logic is a pure function or
sits behind a trait (`Host`), so the Linux suite runs it; the FFI runs only on
Windows. Three jobs run it there:

- `test` on `windows-latest`: the workspace tests with the FFI round trips,
  `install.ps1` on PowerShell 7 and 5.1,
  the reader differential, the developer hook bench (130 ms p95), and the parse and
  refusal of `scripts/locked-windows/*.ps1` and `scripts/lock-check/windows-vm.ps1`.
- `locked-windows` on `windows-2022` and `windows-2025`, elevated (the runners are
  admins with UAC off): `scripts/locked-windows/run.ps1` makes local users, squats both
  pipes before install, installs the ci-locked build, reads every descriptor back,
  runs hooks as a standard user, checks fail-closed (daemon stopped, pipe squatted),
  runs the attacks (DLL planting, `DefineDosDevice`, share-mode-0 opens,
  `TerminateProcess` on the hook and across users, service control), approves from a
  third account, turns lockdown on and off, and reinstalls and uninstalls. The
  measurements are printed as `READBACK` lines for the owner. Its first fully green run
  is the source of the A25 row (§9.2).
- `package-windows` on `windows-2025`: builds the MSI with WiX 5, installs, upgrades
  and removes it, forces a failure after each custom action (`SAIIFE_FORCE_FAIL=1`) to
  check the rollbacks, runs `detect.ps1`, and checks the `.intunewin` header.

**Note (plan 20): the co-signer, `no_verdict` and `0711` in CI.** No new job; new
phases in the existing ones:

- `locked-linux` and `locked-macos`, `phase_cosign` (after `phase_hooks`): an allow
  fixture through the hook and POSTed to `http://127.0.0.1:7433/v1/cosign/claude`
  gets `200` with an empty body; a deny fixture gets the deny body with `saiife denied
  this call`; a hook held in its worker (`SAIIFE_EVAL_FAULT=hang`) and then ended with
  `kill -KILL` gets the deny body with `the saiife hook ended without a verdict` in
  under 7 s, one `hook` record with `event == "no_verdict"` and `bound == true`, and
  `hooks.no-verdict` = warn in `doctor --json`; a POST with no hook gets `no saiife hook
  reported a verdict for this call` after about 8 s; a POST with an `Origin` header
  gets `403`.
- `locked-linux`, `phase_modes` checks `root:root 711` on the binary and that the
  agent cannot read it; `phase_ptrace` (`scripts/locked-linux/ptrace-probe.py`) shows
  that the agent's `PTRACE_ATTACH` and `/proc/<pid>/mem` open on its own hook child
  fail with `EPERM`, while a `0755` copy in its home attaches (the control).
- `locked-windows`, `measure_terminate` keeps its three report-only measurements and
  adds asserted steps: `TerminateProcess(hook, 0)` on a hook held in its worker gives
  `child_exit=0` and a co-sign deny with `the saiife hook ended without a verdict`
  within 7 s, plus a `no_verdict` record with `bound == true` and the agent's SID; a
  hook killed while it waits on stdin gives `no saiife hook reported a verdict for this
  call` (about 8 s) and a record with `bound == false`; the allow and deny controls;
  `doctor --json` has `hooks.no-verdict` = warn and `cosign.listen` = pass.
  `phase_cosign` checks that the service owns the listening port and that the agent
  cannot bind it. A managed hook bench asserts p95 ≤ 130 ms.
- `test (windows-latest)`: `exclusive_addr_blocks_a_second_bind`.

**Note (plan 21): `phase_forge`, after `phase_cosign`.** A forger,
`scripts/locked-windows/forge-allow.ps1` (and `scripts/locked-linux/forge-allow.py`
over the Unix socket, stdlib only), runs as the agent: it sends `hello`,
`hook.begin {agent: "claude"}`, `hook.bind` with the payload's key and an
`audit.append` of a guard record with `decision: "allow"`, then holds the
connection. Asserted steps (each fails the job):

1. **The forged append:** the real hook on `claude/bash-deny.json` held in its
   worker (`SAIIFE_EVAL_FAULT=hang`), the forger on the same payload, the hook
   ended (`TerminateProcess(hook, 0)` on Windows; on Linux and macOS the hook
   exits 2 after the forger appended), then the co-sign POST. The answer is the
   deny body with `the saiife service's own judgment denies this call`, one
   `hook` record with `event == "rejudge_denied"` (with the agent's SID on
   Windows), and `doctor` `hooks.rejudge-denied` = warn.
2. **The hook kill** (plan 20's step, kept): no forger gives the `NoVerdict`
   deny.
3. **The residual control:** a forged append for `claude/bash-allow.json` gives
   an empty `200`, printed as a measurement.
4. **The foreign asker** (Windows): a co-sign request started as the approver
   account for the agent's bound key gives the `NoReport` deny (`Foreign`).
5. **The honest path:** the allow and deny fixtures through the hook and the
   co-signer, and the co-sign latency for the allow fixture after the hook's
   exit (50 runs, p95 printed; report-only until the owner accepts a number,
   target ≤ 300 ms).
6. `doctor --json`: elevated, `cosign.rejudge` = pass, `cosign.asker` =
   pass, `hooks.rejudge-denied` = warn, and `locked.preview` stays info with
   the hint to run `saiife doctor --user <name>` (an elevated `doctor` does
   not run `claude.exe`, so it cannot drop "preview"). Then as the agent,
   `doctor --user <name>` with a stand-in `claude.exe` in its profile (the
   runner has no Claude Code): the `agent-version` check passes and
   `locked.preview` names Codex and Gemini CLI only.

`phase_forge` runs on both `locked-windows` cells, both `locked-linux` cells
and `locked-macos`. Its green run on `windows-2022` and `windows-2025` (CI
run 42673682022: the forged append and the kill denied on both) drops
"preview" for Claude Code (§5.3a). In that run and the one before, a burst
of 8 parallel honest calls from one user gave 8 "no opinion" answers on
Linux, macOS and Windows. The managed hook benches gate again with budgets
per OS set from plan 21's CI measurements: Linux 60 ms p95 (measured 41.2
to 50.0 ms on `ubuntu-24.04`), macOS 40 ms (measured under 40 ms), Windows
130 ms (measured 59.1 ms on `windows-2022` and 59.6 ms on `windows-2025`).
The macOS job also runs the live `pcblist_n` test
(`own_connection_has_own_uid`).

The live lock check on Windows is `scripts/lock-check/windows-vm.ps1`, run by hand
in a throwaway VM; it has not run yet, so every Windows lock label is `unverified`.
ARM64 locked mode is owner handwork until a `windows-11-arm` cell is added.

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

**Note (plan 13): release signing modes.** The release workflow signs each
macOS binary with the hardened runtime, always:

- On a tag push with all six signing secrets (Developer ID certificate and
  its password, identity, team id, notary Apple ID and app-specific
  password): Developer ID, secure timestamp and notarization. A bare
  binary cannot be stapled, so Gatekeeper checks the ticket online.
- Otherwise (no secrets, or not a tag): ad-hoc signed with the hardened
  runtime, not notarized, and the release notes say so. A partial set of
  secrets fails the run.

`system install` requires the hardened runtime and a release build; an
ad-hoc signature only warns, because A4 still holds. On macOS, point 7 is
met with a second uid only: same-user approval is off (§6.10.2).

**Note (plan 19b, W20, W21): Windows release artifacts and signing modes.** A
release adds, per architecture (`x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`):
the zip that `install.ps1` installs, the MSI (`saiife-<version>-x64.msi`,
`saiife-<version>-arm64.msi`) and its `.intunewin`, all in `SHA256SUMS`.
`scripts/release/windows-sign-mode.sh` picks the mode from six Azure Artifact Signing
variables, which the workflow passes on `v*` tag pushes only:

- all six set: `artifact-signing`. Both `saiife.exe` builds, then both MSIs, are
  signed, and `signtool verify /pa` runs after each.
- none set: `unsigned`, with a warning, never a failure; the release notes say so.
- some set: the run fails and names the missing ones.

`system install` on Windows requires a release build (the PE checks of W28); a
missing signature only warns. **v2.2** is done as a preview: locked mode meets points
1, 4 and 7 on Windows Server 2022 and 2025 x64 in CI, with a second account for
point 7. Point 2 waits for the Windows lock check, and point 3 is not met while A25
stands. Plan 21 answers A25 for Claude Code (its co-signed calls are judged by the
service too): `phase_forge` was green on both `locked-windows` cells (CI run
42673682022, the forged append and the kill denied), so for Claude Code v2.2 is
no longer a preview. The managed hook p95 measured 59.1 ms (`windows-2022`) and
59.6 ms (`windows-2025`) against a 130 ms budget. For Codex and Gemini CLI A25
stands, and they stay a preview.

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
| 18 | Fleet packaging (proposed) | v2.x | `.deb`, `.rpm`, and a signed, notarized macOS `.pkg` (after plan 13); MDM recipes (Jamf, Intune, Ansible). Built (plan 18): Linux packages, Ansible, Intune Linux; `.pkg`, Jamf and Intune macOS after plan 13 | 1 |
| 19a/19b | Windows developer mode, then locked mode (§5.3a) | v2.2 | 19a: the PowerShell and cmd guard readers, Windows paths, signed zips and `install.ps1`, the `saiife-win` crate, a `windows-latest` test cell. 19b: the `saiifed` service, named-pipe IPC, SDDL ACLs, same-user approval off (a second account approves), MSI, Intune and GPO recipes, a `locked-windows` CI job. Built (plan 19b): all of it, shipped as a **preview** (A25, §9.2); the `locked-windows` (Server 2022 and 2025) and `package-windows` jobs; the Windows lock-check harness, not run yet. Next: plan 20 | 4 |
| 20 | A killed or crashed hook never counts as an allow | v2.2 | The Claude Code co-signer HTTP hook on `127.0.0.1:7433` (§6.1.1, §8.3); hello-first hooks and the `hook` record with decision `no_verdict` for every agent (§8.5), record only; the Linux binary at `0711` (§5.2); `doctor` checks `cosign.listen` and `hooks.no-verdict`; CI phases in `locked-linux`, `locked-macos` and `locked-windows` (§13). Codex and Gemini CLI get detection only. Windows locked mode stays a preview: code injected into the hook is not prevented (A25). Next: the service judges each co-signed input itself | — |
| 21 | The service judges each co-signed call itself | v2.2 | The co-signer allows only when the hook's verdict and the service's own lexical judgment agree, on Linux, macOS and Windows (§6.1.1): `FsView::Lexical` in the guard, a warm `__eval --serve` pool as the service account, the `rejudge_denied` and `rejudge_failed` records (§8.5). Who asks: `/proc/net/tcp` (Linux), `pcblist_n` (macOS), the TCP table plus the process tree at depth 3 (Windows, §5.3a.2). Claude Code's managed hook judges in-process, and the built-in packs are prebuilt (§6.1.2). `doctor` checks `cosign.rejudge`, `cosign.asker` and `hooks.rejudge-denied`, and `locked.preview` names Codex and Gemini CLI only (§6.16). `phase_forge` in the `locked-*` jobs (§13). Windows locked mode is not a preview for Claude Code (`phase_forge` green on `windows-2022` and `windows-2025`, CI run 42673682022); Codex and Gemini CLI stay preview. Not closed: the restart-window port squat (A25) | — |

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
| Daemon-side guard evaluation | Cut as: needs the agent user's view of the filesystem, and gains nothing against an agent that skips the hook (§9.4). **Partly reversed in plan 21, for Claude Code's co-signed calls only, lexical** (§6.1.1). Both halves of the reason change there. The view: the service does not need it, because the facts only that view gives (a symlink, a junction, a glob's matches, a directory's contents, the project config) are facts that code of the agent's user can change after any judgment anyway (A21); the hook keeps judging them as a second vote. Skipping the hook: the co-sign request comes from Claude Code because of the managed drop-in, not from the hook, so a forger can silence or fake the hook but not this request. What it gains: a forged allow of a denied call is denied (A25). For Codex and Gemini CLI the cut stands: they have no HTTP hook, so nothing reaches the daemon that the hook does not send. |
| Model-provider key brokering | Not in v2 (owner decision 5). The agent holds its own model login, or the company runs a local model. |

## 17. Open questions

All six questions of the first draft are answered (§0, decisions 1–5 and 9).
None is open for v2.0. These remain, for later plans:

1. **macOS minimum version for v2.1** (plan 13). The proposal is the oldest
   macOS that Apple still updates when plan 13 starts. Answered (plan 13,
   decision 13): **macOS 15** (Sequoia), the oldest macOS Apple still
   updates in October 2026. Install refuses anything older.
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
