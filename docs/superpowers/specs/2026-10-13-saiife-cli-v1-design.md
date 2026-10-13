# saiife CLI v1 — design

**Date:** 2026-10-13
**Status:** draft, awaiting review
**Repo:** `HrRobinson/saiife` (new, public, MIT for now — license is a separate decision)

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

## 2. Decisions

| # | Decision | Chosen | Deferred to v2 |
|---|---|---|---|
| D1 | Who installs/controls | Developer, per project | Admin lock (§9.1) |
| D2 | Secrets | `core.secrets` protection pack | Secret broker (§9.2) |
| D3 | Audit | All decisions, masked, terminal + HTML report | Tamper-evident log (§9.3) |
| D4 | Build approach | All Rust, one binary | — |
| D5 | Local models | Documented, tested recipe only (no new code) | — |

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
  guard/    engine, lexer, packs, payload parsing   (moved from saiifeguard)
  audit/    record, mask, write, read, HTML report
  agents/   one module per agent: detect, install hook, remove hook
  cli/      the `saiife` binary; thin command layer over the three above
packs/      *.toml rule packs (embedded in the binary at build time)
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
| `saiife status` | Per agent: hooked or not; active packs; time of last hook invocation for this project (from the audit log). |
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
| Claude Code | `.claude/settings.json` | `PreToolUse` | `Bash`, `Read`, `Grep` |
| Codex | `.codex/config.toml` | `PreToolUse` | `Bash` (shell) |
| Gemini CLI | `.gemini/settings.json` | `BeforeTool` | shell tool, `read_file` |

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
  protection was not effective.
- `input` is the command for shell tools and the path for read tools.

### 6.3 Masking

Applied to `input` before writing; plaintext secrets never reach disk.
Patterns (each replaced by `[MASKED]`):

- GitHub tokens (`ghp_`, `gho_`, `ghs_`, `github_pat_`)
- AWS access key IDs (`AKIA…`, `ASIA…`) and `aws_secret_access_key=`
- `Authorization:` / `Bearer …` values
- `--password`/`--token`/`--secret`/`--api-key` flag values (`=` and space forms)
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

## 7. Secret protection — `core.secrets` (default on)

### 7.1 Shell command rules

Deny reading or exfiltrating:

- `.env`, `.env.*` (except `.env.example`, `.env.sample`, `.env.template`)
- `~/.ssh/id_*` (not `*.pub`), `~/.ssh/config` is allowed
- `~/.aws/credentials`, `~/.config/gcloud/**`, `~/.azure/**`, `~/.kube/config`
- `.npmrc`, `.pypirc`, `.netrc`, `~/.docker/config.json`

…via `cat`, `less`, `more`, `head`, `tail`, `grep`, `sed`, `awk`, `base64`,
`xxd`, `cp`, `scp`, `curl -d @…`/`-F …=@…`.

Deny environment dumps: bare `env`, `printenv` (no args), `set` (no args),
`export -p`, `declare -x`.

### 7.2 Path rules (new engine capability)

Agents' built-in file tools bypass the shell. The guard gains a second
evaluation entry point, `evaluate_path(tool, path)`, used when the hook
payload is a read tool (§5.2). `core.secrets` declares path globs evaluated
there. Paths are canonicalized (resolve `~`, `..`, symlinks where possible)
before matching.

### 7.3 Stated limitation

v1 protects against accidental and obvious secret access, not a determined
adversarial agent (e.g. writing and running a script that reads the file).
This is stated plainly in the docs. The secret broker (§9.2) is the
structural fix.

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

## 9. Scoped for v2 (designed, not built)

### 9.1 Admin lock

An admin installs saiife system-wide and writes hooks into each agent's
system-level policy location (e.g. Claude Code managed settings), which users
cannot override. `.saiife/config.toml`'s `locked` field and a system-level
`/etc/saiife/config.toml` take precedence over project config. v1 reserves the
field and the precedence order; it does not implement enforcement.

### 9.2 Secret broker

`saiife secret add <name>` stores a secret in the OS keychain.
`saiife run --secret <name> -- <cmd>` runs `<cmd>` with the secret injected
into its environment only; the agent sees the name, never the value. Output
is scanned and the value masked. Requires a keychain backend per OS.

### 9.3 Tamper-evident audit

Each record carries `prev` = SHA-256 of the previous line;
`saiife audit verify` reports any break in the chain. The `v` field in §6.2
allows adding this without breaking v1 readers.

Also out of v1: Windows, a central multi-machine dashboard, the Electron app.

## 10. Testing

- **Guard:** all 20 existing test files move over unchanged and stay green.
  Every pack (12 in total) has a dedicated corpus test with deny and allow
  cases; `core.secrets` also tests path rules and the `.env.example` allow.
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
3. All 12 packs tested, each with its own docs page.
4. `saiife audit --report` produces an HTML report a non-developer can read.
5. Full test suite passes with networking disabled.
6. A 3-minute demo runs end to end: install → `init` → agent attempts
   `rm -rf` and reading `.env`, both blocked → `audit --report`.
7. Codex + Ollama recipe documented and manually verified.

Estimate: 4–5 weeks of evenings.
