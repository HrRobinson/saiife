# Threat coverage

This page says which risks saiife covers and which it does not, for each way
of working. It is meant for anyone who decides whether an AI coding agent may
run on a company machine, including people who do not write code.

## The wording rule

saiife brokers credentials for external services (Shopify, HubSpot, GitHub,
your own HTTP APIs). It does not broker the agent's own model login. The
exact claim is: the agent never holds a credential for a brokered service; it
holds its own model-provider login unless you run a local model.

## The threats

saiife looks at three kinds of agent behavior, from easiest to hardest to
stop:

| Threat | Example | Stopped by |
| --- | --- | --- |
| **Mistake** | Agent runs `rm -rf` on the wrong path, force-pushes, reads `.env` while debugging | The guard packs |
| **Helpful bypass** | Agent on auto mode sees a block and "fixes" it by turning saiife off or editing its config | `core.self` in developer mode; root-owned managed hooks and config in locked mode |
| **Determined bypass** | Agent writes and runs a script that reads secrets, or calls an API directly with a key it found | Locked mode: the connector gateway (no key for a brokered service) and an audit the agent cannot write; the [egress recipe](egress.md) for exfiltration |

## Pick your setup

saiife v2.0 has four ways of working. Each has its own table below.
Legend: **covered**, **partly**, **not covered**.

| Setup | Platform | Section |
| --- | --- | --- |
| Developer: hooks in your own account | any | [Developer](#setup-developer) |
| Personal broker | Linux (macOS: v2.1) | [Personal broker](#setup-personal-broker) |
| Locked, on a person's account | supported Linux | [Locked, person's account](#setup-locked-on-a-persons-account) |
| Locked, on a dedicated agent account (recommended for unattended work) | supported Linux | [Locked, dedicated account](#setup-locked-on-a-dedicated-account) |

Supported Linux in v2.0 means Ubuntu 22.04+, Debian 12+ and RHEL 9+. Macs
(until v2.1), Alpine and containers fall under Developer. An agent whose lock
label is not "lockable" falls back to the Developer column for the first two
rows, even on a locked machine. The label of each agent is on its page:
[Claude Code](agents/claude-code.md), [Codex](agents/codex.md),
[Gemini CLI](agents/gemini.md).

## Setup: Developer

saiife runs as your own user and fails open. This is what v1 is built for,
with a person nearby.

| Threat | Coverage | Why |
| --- | --- | --- |
| Mistake (destructive or secret-reading command) | **Covered** by packs; fails open | A broken saiife lets the action run (`error_allowed`). |
| Helpful bypass | **Partly covered** | [core.self](packs/core.self.md) and `saiife status`. |
| Agent obtains a brokered credential | Not covered | There is no broker. |
| Agent uses an external service beyond rules | Not covered | |
| Agent erases or rewrites the audit | Not covered | Careless edits are caught by the chain; a deliberate rewrite is not (no signing key). |
| Agent's own script does local damage | Not covered | |
| Agent reads your other files and logins | Not covered | |
| Data exfiltration to arbitrary hosts | Not covered | |
| Nested or patched agent without hooks | Not covered | |
| Model-provider login used or copied by the agent | Not covered | |
| MCP servers | Not covered | |
| Attacker with root | Not covered | |
| Tools the agent runs inside its own process without a hook (Codex hosted web search) | Not covered | No hook sees them. |

### Developer: a person nearby

You use the agent and watch what it does, and confirm risky steps when the
agent asks.

| Threat | Coverage | Why |
| --- | --- | --- |
| Mistake | **Covered** | The packs block the common destructive and secret-reading actions. Each pack lists what it does not catch. |
| Helpful bypass | **Partly covered** | [core.self](packs/core.self.md) blocks the usual ways to turn saiife off. `saiife status` shows a removed or changed hook. You are there to notice. |
| Determined bypass | **Not covered** | An agent that writes and runs its own script, or uses a key it found, is not seen. |

### Developer: auto mode or unattended

The agent runs commands without asking you, or runs while nobody watches.

| Threat | Coverage | Why |
| --- | --- | --- |
| Mistake | **Partly covered** | The packs still block known-dangerous actions. But if saiife fails, the action runs and nobody sees it until someone reads the audit log. |
| Helpful bypass | **Partly covered** | [core.self](packs/core.self.md) blocks the usual ways, but an agent that keeps trying may find a way the pack does not know. `saiife status` shows it only when someone runs it. |
| Determined bypass | **Not covered** | As above. |

For agents that run unattended, the developer setup is not enough on its own.
Use locked mode, ideally on a dedicated account.

## Setup: Personal broker

`saiife daemon --user` runs a broker as your own user, with the vault key in
the OS keychain (Linux in this version). It is for trying connectors on your
own machine; **not a security boundary**. Same-user approvals are a workflow
aid, not a control. Setup and limits: [Personal broker](personal-broker.md).

| Threat | Coverage | Why |
| --- | --- | --- |
| Mistake | **Covered** by packs; fails open | As Developer. |
| Helpful bypass | **Partly covered** | [core.self](packs/core.self.md) also blocks the usual ways to stop the broker. It runs as your own user, so this is a mistake layer only. |
| Agent obtains a brokered credential | **Partly covered** | The key is in the keychain; a same-user script can read it (Linux). The guard rules deny the obvious readers; a script that calls the Secret Service is not seen. |
| Agent uses an external service beyond rules | **Partly covered** | There is no boundary; workflow only. The agent can stop the broker and bind its socket. |
| Agent erases or rewrites the audit | Same as Developer | The chain is unsigned: there is no signing key in your own home. |
| Agent's own script does local damage | Not covered | |
| Agent reads your other files and logins | Not covered | |
| Data exfiltration to arbitrary hosts | Not covered | |
| Nested or patched agent without hooks | Not covered | |
| Model-provider login used or copied by the agent | Not covered | |
| MCP servers | Not covered | |
| Attacker with root | Not covered | |
| Tools without a hook | Not covered | |

What the guard rules cannot do here: `core.self` and `core.secrets` catch
mistakes, not a determined script of the same user. They do not see `busctl`
calls such as `StopUnit`, killing a process by a pid read from a file,
scripts that use the Secret Service from a library, or `security export`.
The wording rule at the top of this page is for locked mode. In this setup it
is not guaranteed, because an agent running as the same user can reach the
key: in this mode that is a workflow aid, not a control. Use locked mode when
that matters.

## Setup: Locked, on a person's account

An admin installs saiife as root (`saiife system install`): managed hooks, a
root-owned config, a daemon with its own user and the vault, and an audit the
agent cannot write. The agent runs as you.

| Threat | Coverage | Why |
| --- | --- | --- |
| Mistake | **Covered**; fails closed | The gaps are in the [fail-closed matrix](#fail-closed-matrix). |
| Helpful bypass | **Covered** | Managed settings outrank user and project ones and are root-owned. |
| Agent obtains a brokered credential | **Covered** once imported | A credential that was never imported is still readable (`saiife secret import` moves them into the vault). |
| Agent copies a cloud STS credential (`mode = "sts"`) | **Not covered**, by design | `saiife run --cloud` hands a credential that lasts at most 15 minutes, within a session policy, to one command and anything it starts. Any process of your user can ask the daemon for a lease; the `run_allow` check binds only the honest client. Each lease is a `secret` record and `doctor` warns for every service in STS mode. Sign mode has no such gap. See [Amazon S3](connectors/aws-s3.md#sts-mode). |
| Agent uses an external service beyond rules | **Covered** for brokered services | The daemon checks every call against your policy. |
| Agent erases or rewrites the audit | **Covered** against the agent; **detected** against root with [forwarding](forwarding.md) | |
| Agent's own script does local damage (`rm -rf` inside a script) | **Not covered** | Damage reaches your whole home. |
| Agent reads your other files and logins (SSH keys, browser data, git credentials) | **Not covered** beyond `core.secrets` | |
| Data exfiltration to arbitrary hosts | Not covered | |
| Nested or patched agent without hooks | Not covered | It has no keys and writes no audit. |
| Model-provider login used or copied by the agent | **Not covered, by design** | The agent holds its own model login. |
| MCP servers an admin allowed in locked mode | **Not covered** | Unbrokered, but hooked, audited and warned about. |
| MCP servers behind the gateway | **Covered** (brokered, limited, audited) | Run by the daemon with their tokens in the vault, a per-tool policy and a record of every call. The server's network is **not** sandboxed (Landlock covers files and exec), so a hostile server can still send out what it was given. See [MCP](mcp.md#the-sandbox-and-its-limits). |
| Attacker with root | **Detected** with forwarding | |
| Tools without a hook (Codex hosted web search) | Not covered | Not visible to any hook. |

## Setup: Locked, on a dedicated account

The same install, but the agent runs as a separate account (for example
`agent-shop`) that has no login shell and none of your credentials. This is
the recommended setup for unattended agents.

| Threat | Coverage | Why |
| --- | --- | --- |
| Mistake | **Covered**; fails closed | |
| Helpful bypass | **Covered** | |
| Agent obtains a brokered credential | **Covered** | The account holds no other credentials. |
| Agent copies a cloud STS credential (`mode = "sts"`) | **Not covered**, by design | `saiife run --cloud` hands a credential that lasts at most 15 minutes, within a session policy, to one command and anything it starts. Any process of your user can ask the daemon for a lease; the `run_allow` check binds only the honest client. Each lease is a `secret` record and `doctor` warns for every service in STS mode. Sign mode has no such gap. See [Amazon S3](connectors/aws-s3.md#sts-mode). |
| Agent uses an external service beyond rules | **Covered** | |
| Agent erases or rewrites the audit | **Covered** against the agent; **detected** against root with forwarding | |
| Agent's own script does local damage | **Not covered** | Damage is limited to what the agent account can write. |
| Agent reads the person's other files and logins | **Covered by setup** | The account does not have them. |
| Data exfiltration to arbitrary hosts | **Partly covered** with the [egress recipe](egress.md) (Linux); otherwise not covered | |
| Nested or patched agent without hooks | Not covered | No keys, no audit. |
| Model-provider login used or copied by the agent | **Not covered, by design**, unless the agent uses a local model (Ollama, vLLM): then there is no key | |
| MCP servers an admin allowed in locked mode | **Not covered** | Unbrokered, but hooked, audited and warned about. |
| MCP servers behind the gateway | **Covered** (brokered, limited, audited) | Run by the daemon with their tokens in the vault, a per-tool policy and a record of every call. The server's network is **not** sandboxed (Landlock covers files and exec), so a hostile server can still send out what it was given. See [MCP](mcp.md#the-sandbox-and-its-limits). |
| Attacker with root | **Detected** with forwarding | |
| Tools without a hook | Not covered | |

What still applies in every setup: the guard's own limits (see
[Limits of the guard as a whole](#limits-of-the-guard-as-a-whole) and each
pack's "Not covered" section), such as `cd` not being tracked, dynamic
program names and recursive reads of folders.

## Fail-closed matrix

In locked mode saiife fails closed. These are the cases where an agent's own
hook machinery can still let a call run. saiife answers well inside the
timeout (an internal deadline of 3 s), so the "runs" cells need the parent
process itself to die or hang.

| Failure | Claude Code | Codex | Gemini CLI |
|---|---|---|---|
| saiife reports an error (exit 2 and a reason) | blocked | blocked | blocked |
| guard engine crash | blocked (a worker isolates it; the parent denies) | blocked (same) | blocked (same) |
| `check` parent killed or crashes | blocked (`onFailure`) | **runs** | blocked if the exit code is not 0 or 1 (unverified for signals) |
| hook timeout (10 s) | blocked | **runs** | **runs** |
| daemon down or not answering in 2 s | blocked (saiife denies) | blocked | blocked |
| binary missing | cannot happen to a locked install (root-owned); blocked by `onFailure` anyway | **runs** | possibly blocked (exit 127, unverified) |

## How much a record proves

- Connector, approval, secret, policy, daemon and checkpoint records are
  written by the daemon from its own knowledge. They are authoritative.
- Guard records are a claim by a process running as the agent's user that it
  judged a payload. A determined agent can add records for calls it never
  made, or skip the hooks. It cannot remove or change records once written.
  The report labels guard records "reported by the agent's hook" and
  connector records "seen by saiife".
- Root can stop the daemon, read the vault, rewrite the audit and sign new
  checkpoints with the local key. The only defense is
  [forwarding](forwarding.md): a copy elsewhere keeps the checkpoints root
  signed before the rewrite, and `saiife audit verify --external` shows the
  difference. The audit is tamper-proof against the agent and tamper-evident
  against root, provided logs are forwarded.

## How the developer setup works, in short

- Before the agent runs a command or touches a file, it asks saiife. saiife
  blocks known-dangerous actions and lets everything else run.
- Every decision, allowed or blocked, goes into an audit log outside the
  project. `saiife audit --report report.html` turns it into a page you can
  read and share.
- `saiife status` checks that the guard is still in place and says how to
  fix it if not.
- If saiife breaks or is too slow, the agent's action runs anyway ("fails
  open"). This is on purpose while a person is nearby: a broken guard should
  not stop work. Such cases are recorded as `error_allowed` in the audit log
  where saiife can record them. Locked mode fails closed (`error_denied`).
- saiife runs as your own user. Anything you can do, the agent can do, so a
  determined agent can get around it.

## Not covered by the developer setup

- **A determined agent running as your user.** It can write and run a script
  that reads a secret or rewrites the hook settings. saiife cannot stop this.
  `saiife status` shows changed hooks and settings afterwards.
- **External services.** Without locked mode saiife cannot tell what an HTTP
  call does, so it has no per-service rules (Shopify, HubSpot and so on). It
  does block reading secrets out of cloud tools and secret managers. Locked
  mode brokers them: see [Connectors](connectors/README.md).
- **Tools the hook does not cover**, such as web fetch and MCP tools. Each
  agent page lists which tools are judged:
  [Claude Code](agents/claude-code.md), [Codex](agents/codex.md),
  [Gemini CLI](agents/gemini.md).
- **Other agents.** Only Claude Code, Codex and Gemini CLI are supported.
  Codex and Gemini CLI support is not yet verified on a live install; see the
  "Not yet verified live" section on each agent page.
- **Gaps in each pack.** Every pack page has a "Not covered" section. The
  ones that matter most for this page:
  - [core.secrets: not covered](packs/core.secrets.md#not-covered) (for
    example a recursive read of a folder, or `git show HEAD:.env`)
  - [core.self: not covered](packs/core.self.md#not-covered) (for example a
    shell function named `saiife`)
  - [Limits of the guard as a whole](#limits-of-the-guard-as-a-whole)

## Limits of the guard as a whole

These apply to every pack:

- When a command line names `IFS` (the shell setting for how text is split
  into words), saiife cannot be sure how values from `$(...)` split. It allows
  the command unless a rule blocks it, and records it in the audit log as
  `error_allowed`.
- A here-document inside `$(...)` ends at a line that starts with its end word
  and holds a `)`, as in bash 5.3. Older bash and zsh may end it elsewhere.
- zsh 5.9 and dash read three such here-document shapes differently from
  bash. There, saiife may block a command that those shells would treat as
  plain text. This is the safe direction.
- In developer mode the audit chain has no signing key. Anyone with your user's
  rights can rewrite the whole log and its chain consistently, and
  `saiife audit verify` will call it intact. It catches accidental edits and
  clumsy tampering, not a deliberate rewrite.
- Cutting off the newest records cannot be detected without a checkpoint kept
  somewhere the agent cannot write. That needs locked mode with a forwarded
  copy (`saiife audit verify --external`); developer mode has none.

## Lockdown (locked mode)

`saiife lockdown on [--scope all|connectors] [--reason TEXT]` is the kill
switch for when something looks wrong and you want the agents to stop first and
ask questions later. `saiife lockdown off` lifts it, and `saiife lockdown`
shows the state.

- **Who.** Turning it on: root, users in an `[admin]` group and `[approval]
  approvers`. An approver who is not an admin may only turn it on when it is
  off, or widen it (`connectors` to `all`). Turning it off, narrowing it, or
  replacing an active lockdown (even the same scope with a new reason): root
  and users in an `[admin]` group, or an approver who passes polkit
  re-authentication (`same_user = "reauth"`; the
  CLI says what it is for and starts `pkttyagent` first). Under
  `same_user = "deny"`, or when re-authentication is unavailable, an approver
  who is not an admin cannot make those changes (`reauth_required`,
  `reauth_unavailable`). Anyone else is refused, and every refusal is
  recorded. So an agent running as an approver's user cannot lift lockdown
  without the user's password.
- **`connectors`.** Every connector request is denied (rule `lockdown`), no
  gateway token is issued, and approved requests are not sent. Requests that
  were waiting stay waiting.
- **`all`** (the default). That, and every hook call is denied with `saiife
  lockdown is on: <reason>`. The guard record is still written, with the
  decision `deny` and the rule `lockdown`, and keeps the verdict the guard would
  have given. The agents stop working until it is lifted.
- **It lasts.** The flag is a file in the daemon's state directory and survives
  a restart. If the flag cannot be saved, `lockdown on` says so, and the
  daemon is locked until it restarts but not after.
- **It is a record and a notification.** Each change writes a `lockdown`
  record (who, scope, reason) and sends the `lockdown` event, see
  [notifications](notifications.md).

What it does not do: it does not stop a process that is already running a
command, and it does not touch the network. It stops saiife from letting new
calls through. In developer mode there is no lockdown.
