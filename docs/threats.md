# Threat coverage

This page says which risks saiife v1 covers and which it does not, for each
way of working. It is meant for anyone who decides whether an AI coding agent
may run on a company machine, including people who do not write code.

## The three threats

saiife looks at three kinds of agent behavior, from easiest to hardest to
stop:

| Threat | Example | Stopped by |
| --- | --- | --- |
| **Mistake** | Agent runs `rm -rf` on the wrong path, force-pushes, reads `.env` while debugging | v1 guard packs |
| **Helpful bypass** | Agent on auto mode sees a block and "fixes" it by turning saiife off or editing its config | v1 `core.self` + tamper detection; fully in v2 admin lock |
| **Determined bypass** | Agent writes and runs a script that reads secrets, or calls an API directly with a key it found | v2 connector gateway (agent never holds keys) + v3 isolated runner |

Only v1 exists today. v2 and v3 are designed but not built.

## How v1 works, in short

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
  where saiife can record them.
- saiife runs as your own user. Anything you can do, the agent can do, so a
  determined agent can get around it.

## Setup 1: v1 with a person nearby

You use the agent and watch what it does, and confirm risky steps when the
agent asks. This is what v1 is built for.

| Threat | Coverage | Why |
| --- | --- | --- |
| Mistake | **Covered** | The packs block the common destructive and secret-reading actions. Each pack lists what it does not catch. |
| Helpful bypass | **Partly covered** | [core.self](packs/core.self.md) blocks the usual ways to turn saiife off. `saiife status` shows a removed or changed hook. You are there to notice. |
| Determined bypass | **Not covered** | An agent that writes and runs its own script, or uses a key it found, is not seen. |

## Setup 2: v1 on auto mode or unattended

The agent runs commands without asking you, or runs while nobody watches.

| Threat | Coverage | Why |
| --- | --- | --- |
| Mistake | **Partly covered** | The packs still block known-dangerous actions. But if saiife fails, the action runs and nobody sees it until someone reads the audit log. |
| Helpful bypass | **Partly covered** | [core.self](packs/core.self.md) blocks the usual ways, but an agent that keeps trying may find a way the pack does not know. `saiife status` shows it only when someone runs it. |
| Determined bypass | **Not covered** | As above. |

For agents that run unattended, v1 is not enough on its own. That needs v2
(an admin lock the agent cannot remove, and keys the agent never sees),
which is not built yet. Until then, run `saiife status` and read the audit
report regularly.

## Not covered by v1

- **A determined agent running as your user.** It can write and run a script
  that reads a secret or rewrites the hook settings. saiife cannot stop this.
  `saiife status` shows changed hooks and settings afterwards.
- **External services.** saiife cannot tell what an HTTP call does, so it has
  no per-service rules (Shopify, HubSpot and so on). It does block reading
  secrets out of cloud tools and secret managers.
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
  somewhere the agent cannot write. That needs locked mode (v2) with a forwarded
  checkpoint; developer mode has none.

## Lockdown (locked mode)

`saiife lockdown on [--scope all|connectors] [--reason TEXT]` is the kill
switch for when something looks wrong and you want the agents to stop first and
ask questions later. `saiife lockdown off` lifts it, and `saiife lockdown`
shows the state.

- **Who.** Root, users in an `[admin]` group and `[approval] approvers`. Anyone
  else is refused, and the refusal is recorded. An agent running as its own
  user cannot turn lockdown off.
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
