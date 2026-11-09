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

saiife v2 has four ways of working. Each has its own table below.
Legend: **covered**, **partly**, **not covered**.

| Setup | Platform | Section |
| --- | --- | --- |
| Developer: hooks in your own account | any | [Developer](#setup-developer) |
| Personal broker | Linux, macOS, Windows | [Personal broker](#setup-personal-broker) |
| Locked, on a person's account | supported Linux, macOS 15+, Windows (preview for Codex and Gemini CLI) | [Locked, person's account](#setup-locked-on-a-persons-account) |
| Locked, on a dedicated agent account (recommended for unattended work) | supported Linux, macOS 15+, Windows (preview for Codex and Gemini CLI) | [Locked, dedicated account](#setup-locked-on-a-dedicated-account) |

Supported Linux means Ubuntu 22.04+, Debian 12+ and RHEL 9+. Locked mode on
macOS (v2.1) needs macOS 15 or later; its differences are listed in
[Locked mode on macOS](#locked-mode-on-macos). Windows locked mode (v2.2, Windows
11 23H2+ and Server 2022+) is a preview for Codex and Gemini CLI. For Claude Code it
leaves preview once CI shows a forged hook verdict denied (A25). Its differences are
listed in [Locked mode on Windows](#locked-mode-on-windows). Alpine and containers fall
under Developer. An agent whose lock label is not "lockable" falls back to
the Developer column for the first two rows, even on a locked machine. Lock
labels are per platform, and on macOS and Windows every agent is unverified for now. The label of each agent is on its page:
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
the OS keychain (the Secret Service on Linux, the login Keychain on macOS). It is for trying connectors on your
own machine; **not a security boundary**. Same-user approvals are a workflow
aid, not a control. Setup and limits: [Personal broker](personal-broker.md).

| Threat | Coverage | Why |
| --- | --- | --- |
| Mistake | **Covered** by packs; fails open | As Developer. |
| Helpful bypass | **Partly covered** | [core.self](packs/core.self.md) also blocks the usual ways to stop the broker. It runs as your own user, so this is a mistake layer only. |
| Agent obtains a brokered credential | **Partly covered** | The key is in the keychain; a same-user script can read it (on Linux at once, on macOS after one click the user may give). The guard rules deny the obvious readers; a script that calls the Secret Service or the Keychain from a library is not seen. |
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
| Agent injects code into the hook (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`) | **Covered** | Linux installs only the static release build, at mode `0711`: your user can run it but not read it, so the kernel lets no process of your user trace a running hook or open its memory. macOS installs only a binary with the hardened runtime, which ignores `DYLD_*` (an ad-hoc signed build keeps that, but is not notarized). See [install](install.md). |
| Agent gets you to approve its own request (`same_user = "reauth"`) | **Covered** on Linux; on macOS and Windows the option is off | Linux: polkit asks for your password and shows the request. Same-user approval is off on macOS: the prompt cannot show the request, so approvals need a second account. See [approvals](approvals.md#macos). It is off on Windows too, as the agent could capture the password, and the second account must approve from a separate session. See [approvals](approvals.md#windows). |
| Model-provider login used or copied by the agent | **Not covered, by design** | The agent holds its own model login. |
| MCP servers an admin allowed in locked mode | **Not covered** | Unbrokered, but hooked, audited and warned about. |
| MCP servers behind the gateway | **Covered** (brokered, limited, audited) on Linux; macOS has no gateway in v2.1 | Run by the daemon with their tokens in the vault, a per-tool policy and a record of every call. The server's network is **not** sandboxed (Landlock covers files and exec), so a hostile server can still send out what it was given. See [MCP](mcp.md#the-sandbox-and-its-limits). |
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
| Data exfiltration to arbitrary hosts | **Partly covered** with the [egress recipe](egress.md) (Linux only); otherwise not covered | macOS has no recipe: `pf` has no per-uid firewall to rely on. |
| Nested or patched agent without hooks | Not covered | No keys, no audit. |
| Model-provider login used or copied by the agent | **Not covered, by design**, unless the agent uses a local model (Ollama, vLLM): then there is no key | |
| MCP servers an admin allowed in locked mode | **Not covered** | Unbrokered, but hooked, audited and warned about. |
| MCP servers behind the gateway | **Covered** (brokered, limited, audited) on Linux; macOS has no gateway in v2.1 | Run by the daemon with their tokens in the vault, a per-tool policy and a record of every call. The server's network is **not** sandboxed (Landlock covers files and exec), so a hostile server can still send out what it was given. See [MCP](mcp.md#the-sandbox-and-its-limits). |
| Attacker with root | **Detected** with forwarding | |
| Tools without a hook | Not covered | |

What still applies in every setup: the guard's own limits (see
[Limits of the guard as a whole](#limits-of-the-guard-as-a-whole) and each
pack's "Not covered" section), such as `cd` not being tracked, dynamic
program names and recursive reads of folders.

## Locked mode on macOS

Locked mode on macOS (v2.1, macOS 15 or later) covers what the two locked
tables say, with these differences:

- **Same-user approval is off on macOS.** The password or Touch ID prompt
  cannot show which request it approves, so a same-user agent could trick
  you into approving its own request. `same_user = "reauth"` acts as
  `"deny"`: approvals need a second account, and only root and `[admin]`
  users can lift lockdown. See [approvals](approvals.md#macos).
- **A4 (code injected into the hook).** The protection is System Integrity
  Protection plus the hardened runtime: with both, macOS ignores
  `DYLD_INSERT_LIBRARIES` for the hook. Without SIP it does not (the
  locked-macos CI runners, SIP disabled, loaded an injected library into
  the ad-hoc signed hook), so install refuses and `doctor` fails
  `system.sip` unless `csrutil status` says SIP is enabled. The binary must
  have the hardened runtime. Tagged releases are signed with a Developer ID
  and notarized; other builds are ad-hoc signed (hardened, not notarized),
  and install warns. A4 is still to be verified on a SIP-on Mac
  (OWNER-TODO); CI reports it as skipped while its runners have SIP off.
- **Egress is Linux only.** There is no egress recipe for macOS.
- **The MCP gateway is Linux only** in v2.1 (`[mcp.<name>]` is a load
  error); `saiife mcp` works.
- **Identity.** The uid comes from `LOCAL_PEERCRED`. The pid from
  `LOCAL_PEERPID` is the socket's last user, so nothing is granted on a pid;
  sessions are matched by process name only (attribution).
- **Lock labels** on macOS are unverified until the lock check runs in a
  macOS VM. Until then every agent falls back to the Developer column for
  the hook rows, as above.

## Locked mode on Windows

Windows locked mode (v2.2, plan 19b) is a preview for Codex and Gemini CLI. It covers
what the two locked tables say, with the differences below. The main one is A25: a
process of the agent's own user has full access to the hook, and can end it with exit
0 or forge its allow.

- **Claude Code:** the service judges each call itself (plan 21), and a call runs only
  when the hook and the service both allow it. So a killed hook and a forged allow of a
  call the policy denies are both denied. It leaves preview once the `locked-windows`
  CI job shows both attacks denied; until that run is green, treat it as a preview too.
- **Codex and Gemini CLI:** a killed hook still lets the call run: recorded, not
  prevented; measured in CI on Windows Server 2022 and 2025. Rely
  on the "Mistake" and "Helpful bypass" rows. Do not rely on a row that needs the agent
  to be unable to get past its own hook.

See [Windows: locked mode](windows.md#locked-mode).

The rows below were measured by the `locked-windows` CI job on `windows-2022` and
`windows-2025`, as a standard user, unless they say otherwise.

| # | Attack, as the agent's user | Result on Windows |
| --- | --- | --- |
| A25 | End the hook with `TerminateProcess(hook, 0)`, or forge its allow | The kill still works, and the agent still reads exit 0. A process of the agent's user can also make a forged allow, with no code injection: open the service's pipe, send `hook.begin`, bind the call's key, append an allow, and then end the real hook with `TerminateProcess`. Code injected into the hook (Windows gives a user full access to its own processes) can do the same. What happens next depends on the agent. **Claude Code: denied, by the service's own judgment.** Its second managed hook, an HTTP hook to the service's co-signer on `127.0.0.1:7433`, sends the call to the service. The service judges that input itself, with the system policy of the user who asks, and answers "no opinion" only when the hook recorded an allow and its own judgment allows too. Claude Code takes the stricter of the two hooks' answers. A killed hook recorded nothing, so the call is denied ("the saiife hook ended without a verdict"). A forged allow of a call the policy denies is denied ("the saiife service's own judgment denies this call"), and the daemon writes a `hook` record with `event: "rejudge_denied"`; `doctor` warns (`hooks.rejudge-denied`). The `locked-windows` job is to assert both on `windows-2022` and `windows-2025` (plan 21); until it does, treat Claude Code as a preview too. **Left for Claude Code:** a forged allow of a call the policy allows anyway runs, as it would have. The service judges paths as written and reads no file of the agent's user, so it does not see what only that user's file system decides: a symlink, a junction, a glob's matches, and the extra packs of the project's own config. The hook checks those, and a forged verdict skips them. Code of the agent's user can change all of them after any judgment anyway (A21). Also not prevented: a program that takes `127.0.0.1:7433` while the service restarts, which can answer "no opinion" (accepted by the owner; a failed bind fails `doctor`). **Codex and Gemini CLI: runs, and is recorded; still a preview.** Recorded, not prevented; measured in CI on Windows Server 2022 and 2025. They have no co-signer. The daemon sees the hook end without a verdict and writes a `hook` record with decision `no_verdict`, and `doctor` warns (`hooks.no-verdict`). There is no automatic lockdown. All of these are the A21 class: the agent's own code, outside the hook. Before plan 20 the call ran and nothing was recorded (the audit's size did not change). On Linux and macOS a kill cannot pick the exit code. In CI a second test account could end the hook too, but only because both accounts were started with `CreateProcessWithLogonW` from one runner session: both carry that session's logon SID (`S-1-5-5-0-…`), which the hook's default access list grants. That is the test's setup, not a hole. |
| A3 | Point `C:` somewhere else with `DefineDosDevice`, so the hook path runs another binary | Refused: `DefineDosDevice` on `C:` failed with error 5 (access denied). |
| A4 | Plant a DLL beside the hook (the Windows form of `LD_PRELOAD`) | **Covered.** Release builds load DLLs only from System32 (`/DEPENDENTLOADFLAG:0x800`, a static C runtime, `SetDefaultDllDirectories`). A planted DLL beside a copy of `saiife.exe` was not loaded. `doctor` checks the build. |
| A5 | Stop, reconfigure or delete the service | Refused: only SYSTEM and Administrators may. The service restarts one second after any failure. While it is down, hooks deny. |
| A6 | Fake the daemon on the pipe `\\.\pipe\saiife` | **Covered.** The daemon makes the first instance and refuses to start if someone else holds the name; clients check the pipe's owner before they send a byte; users cannot add an instance. While the name is squatted, hooks deny. |
| | Lock `saiife.exe` or `config.toml` (open with share mode 0) so hooks cannot start | Not a block: the open works, and hooks kept working. |
| A16 | Become an admin through UAC | Host precondition. An agent user in Administrators, Backup Operators, Server Operators, Hyper-V Administrators or Account Operators is a `doctor` **fail**. It drops to a warning only for Administrators with `ConsentPromptBehaviorAdmin = 1` and `PromptOnSecureDesktop = 1` (elevation then needs the password). |
| A1 | A machine policy that switches the managed hooks off (`HKLM\SOFTWARE\Policies\ClaudeCode`) | A `Settings` value there replaces Claude Code's managed files. Install exits 1 and `doctor` fails `agents.claude.policy` unless it has `"managedSourcesBehavior": "merge"`. Writing `HKLM` needs an admin. |
| A15 | Approve its own request | **Covered.** Same-user approval is off on Windows: approvals need a second account, from a separate session. There is no password prompt to capture. |

Also different on Windows:

- **Identity.** The daemon reads the caller's SID and groups from its token. The pid is
  attribution only. Records carry the `sid`.
- **OpenSSH and tokens.** OpenSSH sessions are probably denied by the pipe's network
  logon deny. A restricted or low-integrity token is never an admin, but keeps its
  other groups, so `group:` rules still match it. See
  [Windows: limits](windows.md#limits).
- **Not on Windows:** the MCP gateway and the egress recipe.
- **Lock labels** on Windows are unverified until the lock check runs in a Windows VM.

## Fail-closed matrix

In locked mode saiife fails closed. These are the cases where an agent's own
hook machinery can still let a call run. saiife answers well inside the
timeout (an internal deadline of 3 s), so the "runs" cells need the parent
process itself to die or hang.

| Failure | Claude Code | Codex | Gemini CLI |
|---|---|---|---|
| saiife reports an error (exit 2 and a reason) | blocked | blocked | blocked |
| guard engine crash | blocked (judged inside the hook: a crash ends the hook, `onFailure` blocks, and the co-signer denies) | blocked (a worker isolates it; the parent denies) | blocked (same) |
| `check` parent killed or crashes | blocked (`onFailure`) | **runs**; recorded | blocked if the exit code is not 0 or 1 (unverified for signals); recorded |
| hook timeout (10 s) | blocked | **runs** | **runs** |
| daemon down or not answering in 2 s | blocked (saiife denies) | blocked | blocked |
| binary missing | cannot happen to a locked install (root-owned); blocked by `onFailure` anyway | **runs** | possibly blocked (exit 127, unverified) |
| `check` ended with exit 0 by a process of the agent's user (Windows, A25) | blocked (co-signer) | **runs**; recorded | **runs**; recorded |
| a forged allow by a process of the agent's user (A25) | blocked (the service's own judgment) | **runs**; recorded | **runs**; recorded |
| co-signer not listening (`127.0.0.1:7433` taken, or the daemon down) | blocked (`onFailure`) | n/a | n/a |
| the service cannot judge the call (no worker, a crash, a timeout) | blocked (co-signer) | n/a | n/a |

"Recorded" means the daemon writes a `hook` record with decision `no_verdict`
(see `saiife audit --kind hook`) and `doctor` warns (`hooks.no-verdict`). The
call still runs, and nothing locks down by itself.

**The co-signer (Claude Code only).** The managed drop-in has a second
`PreToolUse` hook, of type `http`, that posts the call to the daemon at
`http://127.0.0.1:7433/v1/cosign/claude`. The daemon answers with an empty
`200` only when two things hold: the command hook has recorded an allow for
the same session, tool call id and input, and the service's own judgment of
that input allows it too (plan 21). Otherwise it answers deny. It never
answers allow, so Claude Code's own permission prompts still apply.

- **The service's own judgment** runs on Linux, macOS and Windows. It uses the
  input Claude Code sent, the system policy of the user who asks, and that
  user's account paths. It reads no file of the agent's user: it judges paths
  as written, so it does not follow symlinks or junctions, does not expand
  globs, and does not read the project's config. Those stay the hook's checks.
  A call only `[guard] ask` rules deny passes when the same hook connection
  used an approval for that exact command.
- **Who asks** comes from the socket. On Linux the daemon reads the uid that
  owns the client's socket in `/proc/net/tcp`; on macOS it reads `so_uid`
  from `net.inet.tcp.pcblist_n`. On Windows it finds the pid that owns the
  socket in the TCP table, and the hook that bound the call must run under
  that pid, at most 3 parent steps down. On Windows, code of the agent's user
  can start a process under Claude Code and defeat that tie; the service's own
  judgment is the barrier there. If the daemon cannot tell who asks, it
  denies the call and `doctor` fails `cosign.asker`.
- **Stricter than the hook in one case:** `cp review.md .claude`. The service
  cannot tell a folder from a file, so it judges the target as both, and a
  copy into the protected `.claude` folder reads as a write onto it. That
  call is denied. A Claude Code call whose input is over 16 MiB is denied too.
- If nothing listens on the port, `onFailure` blocks every Claude Code call
  and `doctor` fails `cosign.listen`. If the service cannot judge, `doctor`
  fails `cosign.rejudge`, and every Claude Code call is blocked. With a proxy
  set for Claude Code, add `127.0.0.1` to `NO_PROXY`
  ([install](install.md#the-co-signer-and-proxies)).

## How much a record proves

- Connector, approval, secret, policy, daemon, hook and checkpoint records are
  written by the daemon from its own knowledge. They are authoritative. A
  `hook` record with `event: "rejudge_denied"` is the service's own judgment
  of a Claude Code call that the hook had recorded as allowed: a forged
  verdict, or a case where the two judgments differ.
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

## Limits of the guard on Windows

These apply in developer mode and in locked mode. They have run only on CI's Windows
runners. The full list is in
[Windows: limits](windows.md#limits). Most of all, the PowerShell and cmd readers do
not see:

- aliases and functions defined in the same command (`Set-Alias`, `function f {…}`),
- the contents of `.ps1` scripts,
- .NET calls (`[IO.File]::Delete(…)`) and COM objects,
- the registry provider beyond the `core.lock` rules.

Under the PowerShell reading, a line holding these is denied instead of read. Some
writers (`Start-BitsTransfer -Destination`, `Export-Certificate`, `Save-Module`) are
judged only as reads. A budget overrun that no rule denies on its last look (rules
and paths, symlinks and globs included, for a fixed count of system calls) and a
panic stay `error_allowed` in developer mode. A shell line over 256 KiB is denied in
every mode, with a message telling the agent to split it. So is a line that costs too
much to judge even on that last look, or that makes more than 64 Ki words by brace
expansion. A long generated script or brace line can reach those limits too.

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
  re-authentication (`same_user = "reauth"`, Linux only; the
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
