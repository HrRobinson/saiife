# saiife with Claude Code

Claude Code asks saiife before it uses a tool. saiife answers "block" or
says nothing (the tool runs). Every decision goes into the audit log.

## What `saiife init` writes

`saiife init` adds one hook entry to `.claude/settings.json` in the project.
Everything else in that file stays as it was. If the file does not exist,
saiife creates it.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell|Read|Grep|Glob|LS|Write|Edit|MultiEdit|NotebookEdit",
        "hooks": [
          {
            "type": "command",
            "command": "saiife check --hook-exit --agent claude",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

It also creates `.saiife/config.toml` (the packs that are on) and a record of
what it wrote, kept outside the project, so `saiife status` can notice
changes.

**One step left in Claude Code.** Claude Code holds back project hooks until
you accept the workspace trust prompt. Start `claude` in the project folder
and accept it. `/hooks` in Claude Code shows the saiife hook.

## Which tools are judged

| Claude Code tool | Judged as | Main pack |
| --- | --- | --- |
| `Bash` | a shell command (read as POSIX; on Windows this is Git Bash) | all packs that are on |
| `PowerShell` | a shell command, read as PowerShell on every OS | all packs that are on |
| `Read`, `Grep`, `Glob`, `LS` | a file read | [core.secrets](../packs/core.secrets.md) |
| `Write`, `Edit`, `MultiEdit`, `NotebookEdit` | a file change | [core.self](../packs/core.self.md) |

The timeout is 10 seconds. If saiife does not answer in time, or cannot
start, Claude Code runs the tool anyway (it "fails open"). This is on
purpose for v1, where a person is nearby: a broken guard should not stop your
work. When saiife itself hits an error, it allows the tool and records
`error_allowed` in the audit log. A line the PowerShell reader cannot read, such
as a .NET call, is denied instead: see [Windows](../windows.md#shells-and-the-guard).

On Windows, Claude Code's `Bash` tool runs Git Bash and its `PowerShell` tool runs
PowerShell. The hook's matcher names both. A project hooked before the `PowerShell`
tool was added skips the hook for those calls until you run `saiife init` once;
`saiife status` warns `hook matcher predates the PowerShell tool; run saiife init to
update`. See [Windows](../windows.md).

## Turning it off

Run `saiife init --off` in your own terminal, in the project folder. It
removes only the saiife entry from `.claude/settings.json`. If saiife created
the file and nothing else is left in it, the file is deleted. An agent
cannot run `saiife init --off`: [core.self](../packs/core.self.md) blocks it.

## What `saiife status` checks

- The saiife entry in `.claude/settings.json` is still there and unchanged.
  An entry written by an older saiife that covers fewer tools is reported as
  out of date (run `saiife init` to update it).
- Nothing switches Claude Code's hooks off: `disableAllHooks: true` in
  `.claude/settings.json`, `.claude/settings.local.json` or
  `~/.claude/settings.json`, and `allowManagedHooksOnly` or `disableAllHooks`
  in your company's managed settings (`/etc/claude-code` on Linux,
  `/Library/Application Support/ClaudeCode` on macOS).
- When Claude Code last called saiife in this project.
- For every agent: `.saiife/config.toml` is unchanged, and the `saiife` on
  your `PATH` is the same program, at the same version, that ran
  `saiife init`.
- For every agent: no `.saiife/config.toml` below the project that
  `saiife init` did not set up. Hooks run in that folder would use it
  instead of the project's config. The search skips `.git`, `target` and
  `node_modules`, does not follow symlinks, and stops after 20 000 entries.
  So a config inside one of those folders, or behind a symlinked folder, is
  not reported. Such a config can only add opt-in packs; the core packs stay
  on.

Each failed check prints what is wrong and how to fix it, and `status` exits
with code 1.

## Not covered

- Other Claude Code tools are not sent to saiife: for example web fetch, web
  search and MCP tools.
- A determined agent running as your user can get around the guard, for
  example with a script it writes and runs. See [threat coverage](../threats.md).
- Limits of each pack are listed on its page, for example
  [core.secrets](../packs/core.secrets.md#not-covered) and
  [core.self](../packs/core.self.md#not-covered).

## Locked mode (v2)

Lock label on Linux: **lockable** (checked live with Claude Code 2.1.308 on
2026-10-22, see [lock-check](../lock-check.md); results in
`crates/agents/tests/fixtures/lock-check/claude.tsv`).

Lock label on Windows: **unverified**, and Windows locked mode is a preview
([Windows](../windows.md#locked-mode)). saiife installs the managed hook in
`C:\Program Files\ClaudeCode\managed-settings.d\` (`50-saiife.json` and
`60-saiife-mcp.json`), with the command
`C:/ProgramData/saiife/bin/saiife.exe check --managed --hook-exit --agent claude`.
A `Settings` value under `HKLM\SOFTWARE\Policies\ClaudeCode` replaces those files
unless it says `"managedSourcesBehavior": "merge"`; install and `doctor` fail then.
The lock check has not run in a Windows VM yet; the results will go to
`crates/agents/tests/fixtures/lock-check/windows/claude.tsv`. On Windows the
co-signer denies a call whose hook was ended with `TerminateProcess(hook, 0)`.
It does not stop code injected into the hook, which is why Windows locked
mode is still a preview.

Lock label on macOS: **unverified**. saiife installs the same managed hook
in `/Library/Application Support/ClaudeCode/managed-settings.d/`
(`50-saiife.json` and `60-saiife-mcp.json`), but the lock check has not
been run in a macOS VM yet, so the project hook keeps judging and
`saiife status` says so. The results will go to
`crates/agents/tests/fixtures/lock-check/macos/claude.tsv`. When an MDM
profile (`/Library/Managed Preferences/com.anthropic.claudecode.plist`)
also delivers managed settings, Claude Code may ignore the drop-in;
install and `doctor` warn.

On Linux, with saiife's managed settings in `/etc/claude-code/managed-settings.d/`:

- The hook cannot be turned off: `disableAllHooks` in user, project or local
  settings or on the command line, empty user `hooks`, `CLAUDE_CONFIG_DIR`
  and `--setting-sources user` all still ran it.
- If saiife fails (crash, `kill -9`, hang past the timeout, exit 1, or the
  binary is missing), the tool call is blocked.
- The drop-in has a second `PreToolUse` hook, the co-signer: an HTTP hook to
  `http://127.0.0.1:7433/v1/cosign/claude`, with `onFailure: "block"`. The
  daemon answers it with an empty `200` only when the command hook has
  recorded an allow for the same session, tool call id and input; otherwise
  it answers deny. It never answers allow, so your permission prompts still
  apply. Claude Code runs both hooks at once and takes the stricter answer.
  So a hook that is killed, or that exits 0 without recording a verdict, is a
  deny. The drop-in also lists `http://127.0.0.1:7433/*` in
  `allowedHttpHookUrls`, so your own list cannot skip the co-signer.
- If nothing listens on `127.0.0.1:7433`, every call is blocked and `doctor`
  fails `cosign.listen`. With a proxy set for Claude Code, add `127.0.0.1` to
  `NO_PROXY` ([install](../install.md#the-co-signer-and-proxies)).
- A hook that ends without a verdict is also recorded: a `hook` record with
  decision `no_verdict`, and a `doctor` warning (`hooks.no-verdict`).
- An edit to a settings file during a session is caught by the
  `ConfigChange` hook and blocked.
  - The check is presence-based. A user, project or local settings file
    changed mid-session may hold only `$schema`, `model`, `theme`, `verbose`,
    `cleanupPeriodDays`, `includeCoAuthoredBy`, `outputStyle`,
    `spinnerTipsEnabled`, `alwaysThinkingEnabled` and `language`. Any other
    top-level key denies the change, even when only `theme` was edited in a
    file that already holds `permissions`, for example. Such edits apply
    from the next session.
  - A removed settings file, a symlinked one, or one that is not a JSON
    object is denied too, because saiife cannot verify it.
    saiife never follows a symlink here. If `~/.claude/settings.json` is a
    symlink (dotfiles, GNU Stow), every mid-session change to user
    settings is denied and takes effect from the next session.
  - saiife reads the file while Claude Code applies it, so the two race. The
    check is a heuristic that records the attempt and denies it. The real
    control is that managed settings outrank user, project and local ones.
- MCP tools are denied unless their server is listed in
  `[guard.mcp] allow_servers` in `/etc/saiife/config.toml`. Tool names
  are matched against the listed names, and a name that could belong to a
  longer, unlisted server (`mcp__linear__evil__x` when only `linear` is
  listed) is denied. So is a tool part that starts with `_`, because
  Claude Code turns `linear.` into `linear_`, so `mcp__linear___x` could
  come from an unlisted `linear_`. Each is allowed only when the longer
  server is listed too.
- MCP tool calls go through the hook, and managed settings can block MCP
  servers outright.
- `system install` writes `/etc/claude-code/managed-settings.d/60-saiife-mcp.json`.
  It allows saiife's own MCP server only by command
  (`{"serverCommand": ["/opt/saiife/bin/saiife", "mcp"]}`), so a project
  `.mcp.json` cannot define its own server named `saiife`, plus the
  `[guard.mcp] allow_servers` by name (a listed `saiife` is left out; it
  stays allowed only by command). The hook brokers the `saiife` server only
  while that drop-in is in place: a root-owned regular file, not group- or
  world-writable, holding exactly the pin saiife writes. Without it, the
  `saiife` server is judged like any other: its tools are denied unless
  `allow_servers` lists it. Whether Claude Code enforces `serverCommand`
  as documented has not been checked live yet.
  `doctor` warns (`mcp.claude.allowlist`) when the file differs from policy.
- Register the brokered server with
  `claude mcp add saiife -- /opt/saiife/bin/saiife mcp`. The command must be
  exactly that: an extra argument breaks the pin. To make calls that need
  approval wait, use the environment variable instead of `--wait`:
  `claude mcp add -e SAIIFE_MCP_WAIT=5m saiife -- /opt/saiife/bin/saiife mcp`.
  Its tools are
  connector operations (`shopify_orders_list`) and the tools of gateway
  servers (`linear__create_issue`). Third-party servers can run behind the
  gateway instead of in `allow_servers`. See [MCP](../mcp.md).

### Fail-closed matrix (Claude Code)

| Failure | Result |
|---|---|
| saiife reports an error (exit 2 and a reason) | blocked |
| guard engine crash | blocked (a worker isolates it; the parent denies) |
| `check` parent killed or crashes | blocked (`onFailure`) |
| hook timeout (10 s) | blocked |
| daemon down or not answering in 2 s | blocked (saiife denies) |
| binary missing | cannot happen to a locked install (root-owned); blocked by `onFailure` anyway |
| `check` ended with exit 0 by a process of the agent's user (Windows) | blocked (co-signer) |
| co-signer not listening on `127.0.0.1:7433` | blocked (`onFailure`) |

saiife answers well inside the timeout (an internal deadline of 3 s). The
full matrix for all three agents is in [threats](../threats.md#fail-closed-matrix).
What is and is not covered per setup is in [threats](../threats.md).

## Not yet verified live

These come from product docs or research and still need a check on a live
install:

- The input shape of `NotebookEdit` and `MultiEdit` (marked unverified in
  our research).
- The `CLAUDE_CONFIG_DIR` setting, which saiife's rules use for Claude Code's
  own folder. It comes from product docs, not from our research.
- Very large tool inputs (over 1 MiB): saiife should still find every file
  path in them. We have not checked this on a live install.
- A recursive `Grep` of a whole folder without a file pattern: whether Claude
  Code's search skips hidden and git-ignored files as expected.
