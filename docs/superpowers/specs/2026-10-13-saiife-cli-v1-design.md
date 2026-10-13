# saiife CLI v1 — design

**Date:** 2026-10-13
**Status:** approved 2026-10-13; amended 2026-10-13 (self-protection, cloud
secret reads, tamper detection, v2/v3 roadmap)
**Repo:** `HrRobinson/saiife` (private until v1 works, then public; MIT for
now — license is a separate decision)

## 1. Purpose

`saiife` is a single self-contained binary that makes AI coding agents safe to
run on a company machine: it blocks destructive and secret-leaking actions
before the agent performs them, and keeps an audit log a data protection
officer (DPO) can read.

It replaces the Electron app (`localflow`) as the product direction. The
Electron app is frozen, not deleted. Its Rust command guard (`saiifeguard`) is
the foundation of this CLI.

**Target user for v1:** a developer on their own machine (Linux or macOS), who
turns saiife on per project and can turn it off again. Admin-enforced,
non-removable installs are designed for (§9) but not built in v1.

**Agents supported in v1:** Claude Code, Codex, Gemini CLI.

### 1.1 Threat model and product ladder

saiife defends against three kinds of agent behavior, in rising order of
difficulty:

| Threat | Example | Stopped by |
|---|---|---|
| **Mistake** | Agent runs `rm -rf` on the wrong path, force-pushes, reads `.env` while debugging | v1 guard packs |
| **Helpful bypass** | Agent on auto mode sees a block and "fixes" it by turning saiife off or editing its config | v1 `core.self` + tamper detection; fully in v2 admin lock |
| **Determined bypass** | Agent writes and runs a script that reads secrets, or calls an API directly with a key it found | v2 connector gateway (agent never holds keys) + v3 isolated runner |

Each version is a complete, honest product for the threats it covers, and the
docs state which threats a given setup does *not* cover:

- **v1 — Guard + audit.** Catches mistakes, discourages and detects helpful
  bypasses. For agents with a human nearby.
- **v2 — Locked + brokered.** Agents cannot turn saiife off, never see
  credentials, and reach external services only under per-service rules. For
  agents running unattended.
- **v3 — Isolated.** Agents run in a separate OS identity with no access to
  saiife, keys or the audit log. For full autonomy ("give the agent full
  power") on company infrastructure.

### 1.2 Security principles (binding on every version)

1. **Defense in depth.** No single layer is trusted to be complete; each
   version adds a layer and keeps the ones below.
2. **The agent never holds what it must not misuse.** Secrets and API keys
   live outside the agent's reach (v2+); the guard is not the only barrier.
3. **Deny by default for capabilities, allow by default for commands.** v1's
   command guard blocks known-bad and allows the rest (usability). Anything
   that *grants* power — connector access (v2), runner permissions (v3) — is
   denied unless a rule allows it.
4. **Fail open only where a human is present.** v1 developer mode fails open
   (a wedged guard gets uninstalled). Locked mode (v2) and the isolated
   runner (v3) fail closed: if saiife cannot decide, the action is blocked.
5. **Protection must be observable.** Every fail-open, every disabled hook
   and every gap in the audit trail is recorded or reported; silence is never
   read as safety.
6. **The audit trail must outlive the agent.** v1 keeps it outside the
   project; v2 makes it tamper-evident and unwritable by the agent; v3 keeps
   it outside the agent's OS identity entirely.
7. **Offline and local by default.** No telemetry, no phone-home; any network
   use (v2 connector gateway, optional log shipping) is explicit, per service
   and audited.

## 2. Decisions

| # | Decision | Chosen | Deferred to v2 |
|---|---|---|---|
| D1 | Who installs/controls | Developer, per project | Admin lock (§9.1) |
| D2 | Secrets | `core.secrets` protection pack | Secret broker (§9.2) |
| D3 | Audit | All decisions, masked, terminal + HTML report | Tamper-evident log (§9.3) |
| D4 | Build approach | All Rust, one binary | — |
| D5 | Local models | Documented, tested recipe only (no new code) | — |
| D6 | Agent turning saiife off | `core.self` pack + tamper detection in `status` | Admin lock (§9.1), isolated runner (§9.4) |
| D7 | External services (Shopify, HubSpot, clouds) | Cloud CLI secret reads blocked in `core.secrets` | Connector gateway (§9.2) |

D5 rationale: the guard hooks into the *agent*, not the model, so it already
covers agents running against Ollama/vLLM. v1 ships one tested recipe:
Codex + Ollama with saiife.

## 3. What exists today (in `localflow`)

- `guard/crates/saiifeguard` — ~7k lines of Rust. Single-pass shell lexer,
  segmenting on `&&`/`||`/`;`/`|`/`&`, opaque command substitution, `bash -c`
  re-entry, wrapper unwrapping (`sudo`, `env`, …), 50 ms latency budget, fail
  open. CLI: `test`, `explain`, `check`. 20 test files.
- 11 packs, 79 rules: `core.filesystem`, `core.git` (default on);
  `cloud.aws`, `cloud.azure`, `cloud.gcloud`, `container.docker`,
  `container.k8s`, `db.mongo`, `db.mysql`, `db.postgres`, `iac.terraform`
  (opt-in).
- Audit: JSONL, **deny records only**.
- Agent hook wiring (TypeScript, Electron): injected per pane at spawn time via
  temp settings files / `-c` flags. Not reusable as-is in a CLI.
- Secret handling (TypeScript): tied to Electron's keychain; the cloud STS
  runner is a stub. Not carried over.

## 4. Architecture

Rust workspace:

```
crates/
  guard/    engine, lexer, payload parsing, packs/*.toml (embedded at build time)
  audit/    record, mask, write, read, HTML report
  agents/   one module per agent: detect, install hook, remove hook
  cli/      the `saiife` binary; thin command layer over the three above
docs/       one page per pack, install, recipes
```

Each crate has one job and is tested on its own. `cli` depends on the other
three; `guard`, `audit` and `agents` do not depend on each other except that
`cli` passes a guard decision to `audit`.

Carried-over invariants:

- **Fail open.** Any internal error, parse failure or exceeded latency budget
  allows the command. The event is still audited (§6).
- **Latency budget.** 50 ms per evaluation (existing `DEFAULT_BUDGET`).
- **No network.** The binary makes no network calls of any kind (§8).

## 5. Commands

| Command | Behavior |
|---|---|
| `saiife init` | Detect installed agents; write the guard hook into this project's agent configs; create `.saiife/config.toml`. Idempotent. |
| `saiife init --off` | Remove exactly what `init` added. Leave all other user settings byte-for-byte unchanged where the format allows (JSON/TOML key order preserved). |
| `saiife status` | Per agent: hooked or not; active packs; time of last hook invocation for this project (from the audit log). Runs the tamper checks in §7.5 and prints a clear warning for each failure; exit code 1 if any check fails, so it can run in scripts and CI. |
| `saiife check --agent <name>` | Hook mode. Read the agent's pre-tool JSON on stdin, decide, audit, respond in that agent's contract. Fail open. |
| `saiife test "<cmd>"` | Exit 0 allow / 1 deny, reason on stderr. (exists) |
| `saiife explain "<cmd>"` | Full decision trace. (exists) |
| `saiife packs` | List packs: id, default on/off, enabled here, rule count, one-line summary. |
| `saiife audit` | Terminal table. Filters: `--since <dur>`, `--project <path>`, `--blocked`, `--agent <name>`. |
| `saiife audit --report [path]` | Write one self-contained HTML file (§6.4). |

### 5.1 Project config — `.saiife/config.toml`

```toml
version = 1
packs = ["core.filesystem", "core.git", "core.secrets", "db.postgres"]
locked = false   # reserved for admin lock (§9.1); v1 reads and ignores it
```

Default-on packs are always active. `packs` adds opt-in ones. `saiife init`
writes the default-on list explicitly so the file is self-describing.

### 5.2 Agent hook installation

| Agent | File written by `init` | Hook | Tools covered |
|---|---|---|---|
| Claude Code | `.claude/settings.json` | `PreToolUse` | `Bash`; read: `Read`, `Grep`; write: `Write`, `Edit`, `MultiEdit`, `NotebookEdit` |
| Codex | `.codex/config.toml` | `PreToolUse` | shell; file edits (`apply_patch`) if the hook contract exposes them |
| Gemini CLI | `.gemini/settings.json` | `BeforeTool` | shell tool; read: `read_file`; write: `write_file`, `replace` |

Read tools are checked by `core.secrets` path rules (§7.2); write tools by
`core.self` path rules (§7.4). Where an agent's hook contract does not expose a
tool (to be verified per agent), the gap is listed in that agent's docs page
rather than silently assumed covered.

The hook command is `saiife check --agent <name>`, resolved via `PATH`, so a
reinstall/upgrade never leaves stale absolute paths in project files.

Each written hook entry is tagged (e.g. a `saiife` marker field or comment
where the format allows) so `init --off` can find and remove only its own
entries.

Before implementation, the exact current config schema and hook contract of
each agent must be verified against that agent's current docs and a live
install, and recorded as fixture payloads (§10). The localflow TypeScript
installers (`hook-settings.ts`, `codex-hooks.ts`, `gemini-hooks.ts`) are the
starting reference.

## 6. Audit

### 6.1 Storage

- `$XDG_DATA_HOME/saiife/audit/YYYY-MM.jsonl` (default
  `~/.local/share/saiife/audit/` on Linux, `~/Library/Application
  Support/saiife/audit/` on macOS).
- Never inside the project directory, so it cannot be committed by accident.
- Append-only, one file per calendar month. Writes are best-effort: a failed
  write never blocks or alters the decision.

### 6.2 Record

```json
{"v":1,"ts":"2026-10-13T08:14:02.381Z","agent":"claude","project":"/home/u/app",
 "session":"…","tool":"Bash","input":"rm -rf [MASKED]","decision":"deny",
 "pack":"core.filesystem","rule":"rm-root","reason":"…","saiife":"1.0.0"}
```

- `decision` ∈ `allow` | `deny` | `error_allowed`. `error_allowed` records a
  fail-open (crash, parse failure, budget exceeded), so an auditor can see when
  protection was not effective. (v2 locked mode adds `error_denied`, §9.1;
  readers must tolerate unknown decision values.)
- `input` is the command for shell tools and the path for read tools.

### 6.3 Masking

Applied to `input` before writing; plaintext secrets never reach disk.
Patterns (each replaced by `[MASKED]`):

- GitHub tokens (`ghp_`, `gho_`, `ghs_`, `github_pat_`)
- AWS access key IDs (`AKIA…`, `ASIA…`) and `aws_secret_access_key=`
- `Authorization:` / `Bearer …` values
- `--password`/`--token`/`--secret`/`--api-key` flag values (`=` and space
  forms), including hyphenated variants such as `--access-token`,
  `--auth-token`, `--client-secret`, `--secret-key` — but not file-path flags
  such as `--token-file`
- `KEY=value` env assignments where the key matches
  `(?i)(token|secret|password|passwd|api_?key)`
- Credentials in URLs (`scheme://user:pass@host`)
- Private key blocks (`-----BEGIN … PRIVATE KEY-----`)

### 6.4 HTML report

One file, no external resources (inline CSS, no JS dependencies, no fonts or
images from the network). Sections:

1. Summary: period, projects, agents, total decisions, blocked count,
   fail-open count.
2. Blocked actions: time, agent, project, input, pack, reason.
3. Fail-open events.
4. Active packs per project with their rules in plain language.
5. Full decision list (collapsible).

Written for a non-developer reader: plain-language headings, rule
descriptions instead of regexes.

## 7. Secret and self protection — `core.secrets`, `core.self` (both default on)

### 7.1 Shell command rules (`core.secrets`)

Deny reading or exfiltrating:

- `.env`, `.env.*` (except `.env.example`, `.env.sample`, `.env.template`)
- `~/.ssh/id_*` (not `*.pub`), `~/.ssh/config` is allowed
- `~/.aws/credentials`, `~/.config/gcloud/**`, `~/.azure/**`, `~/.kube/config`
- `.npmrc`, `.pypirc`, `.netrc`, `~/.docker/config.json`

…via `cat`, `less`, `more`, `head`, `tail`, `grep`, `sed`, `awk`, `base64`,
`xxd`, `cp`, `scp`, `curl -d @…`/`-F …=@…`.

Deny environment dumps: bare `env`, `printenv` (no args), `set` (no args),
`export -p`, `declare -x`.

Deny reading secrets out of secret managers and cloud CLIs (the agent may
still *use* the cloud CLIs for normal work, subject to the opt-in cloud
packs):

- AWS: `aws secretsmanager get-secret-value`, `aws ssm get-parameter(s)`
  with `--with-decryption`, `aws ssm get-parameters-by-path` with
  `--with-decryption`, `aws iam create-access-key`, `aws sts
  get-session-token`
- GCP: `gcloud secrets versions access`, `gcloud auth print-access-token`,
  `gcloud auth print-identity-token`, `gcloud iam service-accounts keys
  create`
- Azure: `az keyvault secret show|download`, `az account get-access-token`
- Kubernetes: `kubectl get secret(s)` with `-o yaml|json|jsonpath|go-template`,
  `kubectl describe secret(s)`
- Generic: `vault read|kv get`, `op read|item get` (1Password),
  `doppler secrets`, `gh auth token`

### 7.1a Why external services are not covered by rules

A command guard can see `shopify` or `hubspot` CLI calls, but not the intent
of an HTTP call made with `curl`, Python or any other client. Per-service
read/write rules for external APIs are therefore not attempted in v1; they
belong in the connector gateway (§9.2), where saiife — not the agent — holds
the key and sees every request.

### 7.2 Path rules (new engine capability)

Agents' built-in file tools bypass the shell. The guard gains a second
evaluation entry point, `evaluate_path(tool, path)`, used when the hook
payload is a read tool (§5.2). `core.secrets` declares path globs evaluated
there. Paths are canonicalized (resolve `~`, `..`, symlinks where possible)
before matching.

### 7.3 Stated limitation

v1 protects against accidental and obvious secret access and against an
agent "helpfully" switching saiife off. It does not stop a determined
adversarial agent running as the same OS user (e.g. writing and running a
script that reads the file or rewrites the hook config). This is stated
plainly in the docs and in `saiife status`. The structural fixes are the
admin lock (§9.1), the connector gateway (§9.2) and the isolated runner
(§9.4).

### 7.4 Self-protection — `core.self` (default on)

The guard protects itself. Denied, via shell commands *and* via the agents'
write tools (§5.2):

- Disabling or reconfiguring saiife: `saiife init --off`, editing or
  deleting `.saiife/**`, uninstalling or replacing the `saiife` binary
  (`rm`, `mv`, `cp`, `chmod`, `ln` on its resolved path)
- Removing the hook: editing or deleting `.claude/settings.json`,
  `.claude/settings.local.json`, `.codex/config.toml`, `.gemini/settings.json`
  in the project, and the user-level equivalents
  (`~/.claude/settings.json`, `~/.codex/config.toml`, `~/.gemini/settings.json`)
- Touching the audit trail: any write, move or delete under the audit dir
  (§6.1) and the integrity dir (§7.5)
- Stopping the guard indirectly: `PATH` manipulation that shadows `saiife`
  in the same command (`PATH=… claude`), `alias saiife=…`, and setting
  `SAIIFE_AUDIT_DIR` from an agent command

Reading these files stays allowed (agents may need to explain their setup).

A human turns saiife off from their own terminal, not through the agent:
`saiife init --off` run outside an agent works normally, because the hook
only fires inside agent sessions.

### 7.5 Tamper detection

Because v1 cannot fully prevent a same-user bypass (§7.3), it makes one
visible:

- `saiife init` stores a fingerprint (SHA-256) of each hook entry it wrote
  and of `.saiife/config.toml` in an integrity file outside the project:
  `<data dir>/saiife/projects/<sha256 of project path>.json`.
- `saiife status` checks, per project:
  1. every agent hook entry is still present and unchanged,
  2. `.saiife/config.toml` matches its fingerprint,
  3. the `saiife` binary on `PATH` is the one that ran `init` (path + version),
  4. the time since the last audit record, shown next to each hook, so a hook
     that silently stopped firing is visible.
  Each failed check prints a plain-language warning and the fix (`saiife
  init` to restore).
- `saiife check` records `error_allowed` whenever it fails open (§6.2), so
  gaps caused by crashes are visible in the audit trail too.

## 8. Install and offline

- GitHub Releases: prebuilt binaries for `x86_64-unknown-linux-musl`,
  `aarch64-unknown-linux-musl`, `x86_64-apple-darwin`, `aarch64-apple-darwin`,
  built by CI on version tags, with SHA-256 checksums.
- `install.sh`: detects OS/arch, downloads the matching binary, verifies the
  checksum, installs to `~/.local/bin` (or `/usr/local/bin` with sudo).
  Served from the repo's release assets; a `saiife.com/install.sh` alias is
  optional.
- Stretch: Homebrew tap `hrrobinson/tap/saiife`.
- **No network calls** at runtime: no telemetry, no update check. Enforced in
  CI by running the full test suite inside a network namespace with no
  network (`unshare -rn` on Linux).

## 9. Roadmap: v2 and v3 (designed, not built)

These sections fix the direction so v1 decisions do not block them. Each gets
its own spec before it is built, and each must satisfy the principles in §1.2.

### 9.1 Admin lock (v2)

Goal: an agent running as a normal user cannot turn saiife off.

- An admin installs saiife system-wide (root-owned binary in
  `/usr/local/bin`) and writes hooks into each agent's **system-level policy
  location** (e.g. Claude Code managed settings), which users and their
  agents cannot override or remove. Agents whose hook config cannot be locked
  at system level are listed as "not lockable" rather than shown as covered.
- System config `/etc/saiife/config.toml` takes precedence over project
  config; with `locked = true`, a project can add packs but never remove
  them. v1 reserves the `locked` field and this precedence order.
- **Fails closed** (§1.2 rule 4): in locked mode, any internal error, parse
  failure or exceeded budget blocks the action and records `error_denied`.
- The audit log moves to a root-owned directory written by a small
  privileged writer (setuid helper or local daemon), so the agent's user
  cannot edit or delete it.
- `saiife init --off` requires admin rights in locked mode.

### 9.2 Connector gateway (v2) — replaces the plain secret broker

Goal: the agent never holds a credential, and every use of an external
service passes through rules.

- **Vault:** `saiife secret add <name>` stores credentials in the OS keychain
  (v2) or the root-owned store (locked mode). The agent sees names, never
  values.
- **Command use:** `saiife run --secret <name> -- <cmd>` injects the secret
  into `<cmd>`'s environment only; output is scanned and the value masked.
- **Service use (connectors):** saiife runs a local gateway on `127.0.0.1`.
  The agent calls `saiife api <service> <operation>` (or the gateway URL);
  saiife attaches the credential, enforces the service policy and audits the
  request. Starting connectors: Shopify, HubSpot, GitHub, Stripe, AWS, GCP,
  Azure (reusing localflow's connector designs).
- **Per-service policy, deny by default** (§1.2 rule 3):

  ```toml
  [services.shopify]
  allow = ["orders:read", "products:read"]
  ask   = ["products:write"]        # needs a human yes, per request
  deny  = ["customers:export", "*:delete"]

  [services.aws]
  allow = ["s3:read:arn:aws:s3:::reports-*"]
  ```

  Anything not listed is denied. `ask` pauses the request until a human
  approves it in their terminal or via the audit UI.
- **Rate and blast-radius limits** per service (e.g. max 50 writes/hour,
  max 1 bulk operation per session).
- Because the agent holds no keys, a script that bypasses the guard still
  has nothing to authenticate with. This is the structural fix for §7.1a.

### 9.3 Tamper-evident audit (v2)

- Each record carries `prev` = SHA-256 of the previous line; `saiife audit
  verify` reports any break in the chain. The `v` field in §6.2 allows adding
  this without breaking v1 readers.
- Optional, explicit forwarding to the company's log system (syslog, file
  share or SIEM endpoint) so a copy exists outside the machine. Off by
  default; when on, it is the only network use besides connectors and is
  itself audited.

### 9.4 Isolated runner (v3)

Goal: give an agent full autonomy without trusting it.

- `saiife run-agent <agent> [--profile <name>]` starts the agent under a
  **separate OS identity**: a dedicated low-privilege user, or a container /
  lightweight VM where available (Linux namespaces + seccomp; macOS sandbox
  profile or VM).
- The agent sees only the project directory (read-write) and an explicit
  allow-list of other paths (read-only). saiife's binary, config, vault and
  audit log are outside its view.
- **Network egress is deny by default**: the agent can reach the saiife
  gateway (§9.2) and allow-listed hosts (e.g. the model provider or a local
  Ollama). Everything else is dropped and audited.
- Resource limits (CPU, memory, disk, time) and a kill switch
  (`saiife stop <session>`).
- Guard, connector policy and audit from v1/v2 run *outside* the sandbox and
  apply unchanged; the runner **fails closed**.
- Profiles describe what an agent may do (`profile = "shop-support"`: project
  dir + Shopify orders:read + no other network), so companies define "full
  power" per role instead of per agent session.

### 9.5 Also out of v1

Windows, a central multi-machine dashboard (likely the successor of
`saiife-hub`), the Electron app.

## 10. Testing

- **Guard:** all 20 existing test files move over unchanged and stay green.
  Every pack (13 in total: the 11 existing plus `core.secrets` and
  `core.self`) has a dedicated corpus test with deny and allow cases;
  `core.secrets` also tests path rules, cloud secret reads and the
  `.env.example` allow; `core.self` tests shell and write-tool attempts to
  disable saiife, and that *reading* its config stays allowed.
- **Tamper detection:** for each check in §7.5, a test that tampers (remove a
  hook entry, edit `.saiife/config.toml`, swap the binary path) and asserts
  `status` warns and exits 1; an untouched project exits 0.
- **Agents:** per agent, against fixture config files: `init` adds the hook;
  a second `init` is a no-op; `init --off` restores the original file; unrelated
  user settings survive both.
- **Hook payloads:** recorded real payloads for each agent and tool
  (shell + read) as fixtures; `check` tested against them for allow, deny and
  malformed input (must fail open with an `error_allowed` record).
- **Audit:** one masking test per pattern in §6.3; report contains no
  `http://`/`https://` resource references; `--since`/`--blocked` filters.
- **Offline:** CI runs everything with networking disabled (§8).

## 11. Migration

1. Create `HrRobinson/saiife`.
2. Bring `guard/` over from `localflow` with history (`git filter-repo
   --subdirectory-filter guard`), then restructure into the workspace layout.
3. Rename the binary `saiifeguard` → `saiife`; the engine crate keeps its
   internal API.
4. Add a note to the `localflow` README pointing to the new repo. No other
   changes to `localflow`.

## 12. Definition of done (v1)

1. One-line install works on Linux (x86_64, arm64) and macOS (Intel, Apple
   Silicon).
2. `saiife init` guards Claude Code, Codex and Gemini in a project;
   `init --off` reverses it cleanly.
3. All 13 packs tested, each with its own docs page.
4. `saiife audit --report` produces an HTML report a non-developer can read.
5. Full test suite passes with networking disabled.
6. A 3-minute demo runs end to end: install → `init` → agent attempts
   `rm -rf`, reading `.env`, and turning saiife off — all three blocked →
   `audit --report`.
7. Codex + Ollama recipe documented and manually verified.
8. `saiife status` detects a hook removed by hand and says how to restore it.
9. The docs state, per setup, which threats from §1.1 are and are not
   covered.

Estimate: 5–6 weeks of evenings (self-protection and tamper detection add
about one week).
