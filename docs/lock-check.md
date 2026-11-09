# Live lock checks

`scripts/live-check-locked.sh` answers one question for each agent: can a
managed (system-level) saiife hook lock Claude Code, Codex and Gemini CLI, so
that nothing a user or the agent does can switch it off? It runs the real
agents, logged in with your accounts, inside a throwaway Docker container.
For each check it asks the agent to touch a marker file and records whether
the call ran, was blocked, or fired the hook.

The real `saiife check --managed` comes later (plan 9). These checks use a
stub that allows, denies, crashes or hangs on request.

You run this yourself. CI never runs it, and neither do tests or agents.

Lock labels are per platform. The Docker run gives the Linux labels. The
macOS labels come from the same checks run in a throwaway macOS VM
([macOS, in a throwaway VM](#macos-in-a-throwaway-vm)); until that has been
done, every agent is `unverified` on macOS. The Windows labels come from a
throwaway Windows VM ([Windows, in a throwaway VM](#windows-in-a-throwaway-vm));
that harness has not run yet, so every agent is `unverified` on Windows.

## What it touches on your machine

It touches only these:

- the Docker image `saiife-lockcheck:local`. The image is built from
  [the Dockerfile](../scripts/lock-check/Dockerfile) on stdin, with no build
  context, so no repo files and no secrets go into it;
- the named volume `saiife-lockcheck-home`, which holds the agents' home
  directory and your logins;
- `target/lock-check/` in this repo, where the results go.

The container gets 4 mounts: `scripts/lock-check` and
`crates/agents/tests/fixtures/managed` (both read-only), the output
directory, and the volume. Nothing from your home folder is mounted, and the
script never copies agent configs or credentials. All root actions happen
inside the container, which runs with `--ulimit core=0` and
`--security-opt no-new-privileges`. The result files are handed to your user
when they are created and again at the end of each run (rootful Docker only).

**Crash reporter entries.** The three `*.fail.segv` checks crash a bash
inside the container with a real SIGSEGV, to see how each agent treats a
crashing hook. `core_pattern` is a kernel-wide setting, so your host's crash
handler (systemd-coredump, or a desktop crash reporter) may log or pop up as
many as 3 entries for `/usr/bin/bash` during a full run. No core file is
written. You can dismiss them.

## Commands

From the repository root:

```sh
bash scripts/live-check-locked.sh --setup      # once: log in to the agents
bash scripts/live-check-locked.sh all          # or: claude | codex | gemini
bash scripts/live-check-locked.sh --rebuild all
bash scripts/live-check-locked.sh --print codex
bash scripts/live-check-locked.sh --forget
```

- `--rebuild` rebuilds the image first. To pin versions, set
  `CLAUDE_VERSION`, `CODEX_VERSION`, `GEMINI_VERSION` or `NODE_VERSION`.
- `--print` shows the `docker run` arguments and runs nothing.
- `--forget` deletes the volume, and with it your logins.
- `AGENT_TIMEOUT` sets the limit for each agent run, in seconds (default 240).
  A full run takes a while, because every check is one real agent turn.
- You can pipe the output, for example `... all | tee run.txt`. The script
  asks Docker for a TTY only when it has one.

## Logging in (`--setup`)

`--setup` opens a shell in the container as the user `agent`. Log in to each
agent there, then type `exit`:

- Claude Code: run `claude`, type `/login`, follow the steps, then `/exit`.
- Codex: `codex login --device-auth`
- Gemini CLI: run `gemini`, choose "Login with Google", then `/quit`.

The logins stay in the volume until you run `--forget`.

Some checks (`*.config-dir`, `codex.codex-home`, `gemini.gemini-home`) run
the agent with a second home, `~/alt`, which reaches your login files through
symlinks. Suppose an agent refreshes its token by writing a new file in place
of the symlink. The refreshed token is then deleted when the check is reset,
and the real file may keep an old refresh token that is no longer valid.
Later checks would then fail to log in and read `inconclusive`. If you see
that, run `--setup`, log in again, and rerun.

## Reading the results

Each agent run writes two files:

- `target/lock-check/<agent>-<UTC time>.tsv`: the result rows.
- the matching `.log`: everything the agent printed, for each check.

The terminal shows the same table at the end of the run, with any hints
repeated below it.

Each row has these fields:

| Field | Meaning |
| --- | --- |
| `id` | The check, e.g. `codex.features-off.user` |
| `class` | `control` (the agent works at all), `gate` (a way to switch the lock off; must hold), `gap` (a hook failure the spec lets run), `caveat` (a known bypass the label tolerates), `design` (a question for plan 9; never affects the label), `info` |
| `expect` / `observed` | `ran` (marker touched), `blocked` (the call was attempted, seen by the witness hook, and denied by the stub), `fired` / `not-fired` (the stub was called), `unavailable` (an MCP tool was hidden), `found` / `not-found` (probe rows), `inconclusive`, `unsupported` |
| `status` | `PASS` (observed = expect), `FAIL` (it differs), `ERROR` (observed `inconclusive`: there is no evidence either way, for example the model never tried the tool), `SKIP` (`unsupported`: the agent rejected a flag this version lacks), `INFO` (info rows) |
| `detail` | The stub mode, the agent's exit code, `stub=seen/unseen`, `witness=seen/unseen`, and sometimes a `hint:` |

The run ends with a lock label: the `.tsv`'s last line (`# label=<id>`),
the end of the table, and the wrapper's summary for each agent.

| Label id | Wording | Meaning |
| --- | --- | --- |
| `lockable` | lockable | Every gate held |
| `lockable-with-gaps` | lockable, fail-open gaps listed | Gates held. Some hook failures (crash, timeout, missing binary) let the call run |
| `lockable-with-caveats` | lockable with caveats | Gates held. A known bypass (a `caveat` row) worked |
| `not-lockable` | not lockable | A gate failed: a user or project setting, a flag or an environment variable switched the managed hook off |
| `unverified` | unverified | A gate or the control was `inconclusive`. Read the hint or the `.log`, then rerun |

The wrapper exits 0 only if no label is `not-lockable` or `unverified`.

Some hints and what they mean:

- **`hint: the witness hook did not log this call`** on the control row.
  The witness is a second managed hook that proves a tool call happened, and
  it is not working. Every `blocked` row will then read `inconclusive`.
- **`check LOCKCHECK_CODEX_REQUIREMENTS`** on `codex.managed.fires`. Codex
  probably reads its managed file from another path. The `path-probe` row
  lists the `/etc/codex/*` paths found in the installed binary.
- **`check LOCKCHECK_GEMINI_TOGGLE / enable key`** on `gemini.system.fires`.
  Gemini's hooks are probably off by default, and the probe missed the key
  that switches them on.
- **`gemini.toggle-off.user` reads `inconclusive` with "no hooks toggle
  found"**. The probe found no hooks on/off key in the installed Gemini.
  Set `LOCKCHECK_GEMINI_TOGGLE` and rerun.

Gemini has no command-line gate row on purpose. Gemini CLI has no flag that
loads a settings file or switches hooks off; only settings files and
environment variables do. The `gemini.cli.settings-flag` probe rechecks this
against `gemini --help`. If it reads `found`, a command-line gate row is due.

## Claude Code needs a stand-in co-signer

The Claude Code checks install the managed fixture
`crates/agents/tests/fixtures/managed/claude/50-saiife.json`. Since plan 20
it has a second `PreToolUse` hook: an HTTP hook to
`http://127.0.0.1:7433/v1/cosign/claude`, with `onFailure: "block"`. The
checks run a stub, not the saiife daemon, so nothing listens on
`127.0.0.1:7433`. The HTTP hook then fails, and Claude Code blocks every tool
call, so the control row cannot pass and the Claude results mean nothing.

The harness does not start a co-signer yet. Until it does, a run for Claude
Code needs a stand-in co-signer on `127.0.0.1:7433`, inside the container or
VM, for the whole run. It must answer every `POST /v1/cosign/claude` with
`200` and an empty body. An empty `200` is "no opinion" to Claude Code, so
the stub's verdict decides each row, as before plan 20. This stand-in has
not been run yet. A sketch with Python's standard library:

```python
import http.server

class Cosign(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

http.server.HTTPServer(("127.0.0.1", 7433), Cosign).serve_forever()
```

With the stand-in, the Claude rows test the command hook only. They say
nothing about the real co-signer: CI's `locked-*` jobs test that against the
real daemon. Do not leave the stand-in running on a machine where saiife is
installed: it would take the daemon's port and answer for it. Codex and
Gemini CLI have no co-signer and need nothing.

## Knobs (`LOCKCHECK_*`)

Some agent keys and paths are not verified yet. If a hint points at one, set
the variable on the host and rerun. The wrapper passes it into the container
only when it is set.

| Variable | Default | Use it when |
| --- | --- | --- |
| `LOCKCHECK_CODEX_REQUIREMENTS` | `/etc/codex/requirements.toml` | `codex.managed.fires` is `not-fired` and the path probe names another `/etc/codex/` file. Must be a path under `/etc` without `..` |
| `LOCKCHECK_CODEX_MHO_TABLE` | top level | `codex.managed-only` suggests `allow_managed_hooks_only` belongs in a table, e.g. `hooks` |
| `LOCKCHECK_CODEX_MCP_SNIPPET` | `[mcp_servers.other.identity]` allowlist | The managed MCP allowlist key turns out to be spelled differently |
| `LOCKCHECK_GEMINI_TOGGLE` | probed from the installed schema | The probe finds no key, or the wrong one. Give keys separated by spaces, e.g. `hooksConfig.enabled` |

Example:

```sh
LOCKCHECK_GEMINI_TOGGLE="hooksConfig.enabled" bash scripts/live-check-locked.sh gemini
```

## macOS, in a throwaway VM

`scripts/lock-check/macos-vm.sh` runs the same check tables against the
macOS paths of spec §5.3:

| Agent | Managed path on macOS |
|---|---|
| Claude Code | `/Library/Application Support/ClaudeCode/managed-settings.d/` |
| Codex | `/etc/codex/requirements.toml` |
| Gemini CLI | `/Library/Application Support/GeminiCli/settings.json` |

It writes those system-wide files and runs the agents as a standard user, so
it runs only inside a throwaway macOS VM, as root through `sudo`. It refuses
(exit 2) before it touches anything unless `uname` is `Darwin` and
`SAIIFE_LOCKCHECK_MACOS_VM=1` is set. It also refuses when saiife is
installed or any of those managed files already exists, so run it in a VM
clone where `saiife system install` has not run (or after
`saiife system uninstall --purge`). At exit it removes what it wrote:
`/opt/saiife` (the stub), `/opt/lockcheck` (its copy of the scripts, the run
dir and the project) and the managed files.

Steps (`tart` is one way to get a VM; any throwaway macOS 15 VM works):

1. On your Mac: `brew install cirruslabs/cli/tart`, then
   `tart clone ghcr.io/cirruslabs/macos-sequoia-base:latest saiife-lock` and
   `tart run saiife-lock` (log in as admin/admin).
2. In the VM, as the admin:
   - install Node 22 and the agents system-wide:
     `sudo npm install -g @anthropic-ai/claude-code @openai/codex @google/gemini-cli`;
   - install bash 4+ and GNU coreutils: `brew install bash coreutils`
     (`jq` ships with macOS 15);
   - create a standard (not admin) user `agent` in System Settings, Users
     & Groups.
3. Log in as `agent` once, sign in to each agent (as in
   [Logging in](#logging-in---setup)), then log `agent` out again: the
   harness ends `agent`'s processes after each run and refuses while
   `agent` owns the console.
4. Copy a checkout of this repository into the VM, and from its root run
   `SAIIFE_LOCKCHECK_MACOS_VM=1 sudo -E bash scripts/lock-check/macos-vm.sh all`
   (or `claude`, `codex`, `gemini`).

Results go to `target/lock-check/macos-<agent>-<UTC time>.tsv` and the
matching `.log`, handed to the user who ran `sudo`. Their header has
`# platform=macos`. `AGENT_TIMEOUT` and the `LOCKCHECK_*` knobs below work as
in the Docker run.

**Logins the Keychain holds.** An agent that keeps its login in the macOS
Keychain (Claude Code does on macOS) may not find it in a `sudo` run, because nothing
unlocks `agent`'s Keychain there. The control row then reads `inconclusive`.
Put the login in a root-owned file of `NAME=value` lines, mode 0600, and pass
it with `LOCKCHECK_AGENT_ENV_FILE=/var/root/lockcheck.env`; the harness adds
those variables to every agent run and never writes them to the log (for
Claude Code, the token from `claude setup-token` as
`CLAUDE_CODE_OAUTH_TOKEN`). Delete the file afterwards.

**The Claude drop-in.** On macOS saiife installs Claude Code's managed hook
as a drop-in in `managed-settings.d/`, as on Linux. `claude.managed.fires`
and the `claude.deny` row show whether Claude Code reads drop-ins there. If
they do not fire, say so: install then switches to the whole file
`managed-settings.json`.

## Windows, in a throwaway VM

`scripts/lock-check/windows-vm.ps1` runs the same check tables against the
Windows paths of spec §5.3a:

| Agent | Managed path on Windows |
|---|---|
| Claude Code | `C:\Program Files\ClaudeCode\managed-settings.d\` |
| Codex | `C:\ProgramData\OpenAI\Codex\requirements.toml` |
| Gemini CLI | `C:\ProgramData\gemini-cli\settings.json` |

**It has not run yet.** No Windows recording exists. The first run in a VM
will show which of its assumptions hold. Expect to fix the harness on that
first run.

It writes those system-wide files and runs the agents as a standard user, so
it runs only inside a throwaway Windows VM, elevated. It refuses (exit 2)
before it touches anything unless the OS is Windows and
`SAIIFE_LOCKCHECK_WINDOWS_VM=1` is set. It also refuses when the `saiifed`
service exists, when `HKLM\SOFTWARE\Policies\ClaudeCode` exists (Claude Code
would ignore the files), or when any managed file, `C:\ProgramData\saiife` or
`C:\lockcheck` already exists. At exit it removes what it wrote.

How it works:

- Git Bash runs the check tables (`lib.sh` with `LOCKCHECK_PLATFORM=windows`)
  against a staging dir, where `C/Program Files/ClaudeCode/...` stands for
  `C:\Program Files\ClaudeCode\...`.
- Git Bash cannot start a program as another user. So each agent run is a
  plan: the managed files, the settings files, the project and the prompt.
  The script writes the plan's files to `C:\`, starts the agent through Git
  Bash as the local user `agent`, and hands the logs and markers back. The
  tables then observe and record as on Linux.
- The managed hooks run the real W9 command,
  `C:/ProgramData/saiife/bin/saiife.exe check --managed --hook-exit --agent <a>`.
  That `saiife.exe` is a small launcher, compiled in the VM with the .NET
  Framework's `csc.exe`, that runs the stub in Git Bash. The witness is a
  launcher too.
- Prompts for Codex and Gemini CLI use `New-Item`, as their shell is
  PowerShell. Claude Code's prompts use `touch`, as its `Bash` tool is Git
  Bash.

Steps:

1. Make a Windows 11 23H2 or Server 2022 VM, and a standard (not admin)
   local user `agent`.
2. As an admin, install PowerShell 7, Git for Windows, `jq` (on the admin's
   `PATH`) and Node 22.
3. Log in as `agent`, install the agents for that user
   (`npm install -g @anthropic-ai/claude-code @openai/codex @google/gemini-cli`),
   sign in to each, then log `agent` off.
4. Copy a checkout of this repository into the VM. From its root, in an
   elevated PowerShell 7:
   `$env:SAIIFE_LOCKCHECK_WINDOWS_VM = '1'; pwsh -File scripts\lock-check\windows-vm.ps1 -Agent all`.
   It asks for `agent`'s password once.

Results go to `target\lock-check\windows-<agent>-<UTC time>.tsv` and the
matching `.log`. Their header has `# platform=windows`.

What the first run must settle:

- Which shell each agent uses for hooks on Windows. The launchers do not care,
  but a user hook that `touch`es a marker does.
- How the stub's crash modes (`segv`, `kill9`, `hang`) look through the
  launcher, and whether a hung stub is ended with the agent's hook.
- Whether `ln -s` in Git Bash makes the login links that the alternate config
  dir checks need. If it does not, those rows read `inconclusive`.
- The trust key Codex writes for the project on Windows.
- The agent's settings files are replaced by the harness's and are not kept.
  Use a fresh VM clone.

## What to send back

Send the newest `target/lock-check/<agent>-*.tsv` for each agent. Add the
matching `.log` files if any row is `FAIL`, `ERROR` or has a `hint:`. These
results become the fixtures under `crates/agents/tests/fixtures/lock-check/`
and the "Locked mode" line on each agent page. The macOS results
(`macos-<agent>-*.tsv`) become
`crates/agents/tests/fixtures/lock-check/macos/<agent>.tsv`, and the macOS
labels follow them. The Windows results (`windows-<agent>-*.tsv`) become
`crates/agents/tests/fixtures/lock-check/windows/<agent>.tsv` in the same way.

When you are done, `--forget` removes the logins. The image stays until you
remove it with `docker image rm saiife-lockcheck:local`.
