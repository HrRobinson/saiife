# saiife with Codex

Codex asks saiife before it runs a shell command or changes a file. saiife
answers "block" or says nothing (the tool runs). Every decision goes into the
audit log.

## What `saiife init` writes

`saiife init` adds one hook entry to `.codex/config.toml` in the project.
Your comments, key order and formatting in that file stay as they were. If
the file does not exist, saiife creates it.

```toml
[[hooks.PreToolUse]]
matcher = "^(Bash|apply_patch)$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "saiife check --hook-exit --agent codex"
timeout = 10
statusMessage = "saiife guard"
```

If you already wrote your hooks in the short inline form
(`PreToolUse = [{ ... }]`), saiife adds its entry to that list in the same
form instead.

It also creates `.saiife/config.toml` (the packs that are on) and a record of
what it wrote, kept outside the project, so `saiife status` can notice
changes.

**One step left in Codex: trust the hook.** Codex asks you to trust every new
or changed hook once. Start `codex` in the project folder (the project's
`.codex` folder must be trusted), run `/hooks` and trust the saiife hook.
Until you do, the hook does not run. After `saiife init` updates the entry,
Codex asks again.

## Which tools are judged

| Codex tool | Judged as | Main pack |
| --- | --- | --- |
| `Bash` | a shell command | all packs that are on |
| `apply_patch` (also used for Codex's `Edit` and `Write`) | a file change, for each file named in the patch | [core.self](../packs/core.self.md) |

Codex reads files with shell commands, so reads are judged as shell commands
(for example `cat .env` is blocked by
[core.secrets](../packs/core.secrets.md)). This is unverified: we have not
checked it on a live install.

The timeout is 10 seconds. If saiife does not answer in time, or cannot
start, Codex runs the tool anyway (it "fails open"). This is on purpose for
v1, where a person is nearby. When saiife itself hits an error, it allows the
tool and records `error_allowed` in the audit log.

## Turning it off

Run `saiife init --off` in your own terminal, in the project folder. It
removes only the saiife entry from `.codex/config.toml`. If saiife created
the file and nothing else is left in it, the file is deleted. An agent
cannot run `saiife init --off`: [core.self](../packs/core.self.md) blocks it.

## What `saiife status` checks

- The saiife entry in `.codex/config.toml` is still there and unchanged.
- Nothing switches Codex's hooks off: `[features] hooks = false` in the
  project's `.codex/config.toml` or in `~/.codex/config.toml`.
- When Codex last called saiife in this project.
- For every agent: `.saiife/config.toml` is unchanged, and the `saiife` on
  your `PATH` is the same program, at the same version, that ran
  `saiife init`.

Each failed check prints what is wrong and how to fix it, and `status` exits
with code 1.

`status` cannot see whether you trusted the hook in `/hooks`. The "last hook
call" line shows it: if it says "no call yet" after you used Codex, the hook
is not running.

## Not covered

- Other Codex tools are not sent to saiife: for example MCP tools. Hosted
  tools such as web search do not trigger hooks at all.
- `codex --profile` can pick a user profile with other hook settings.
- `status` does not check company-managed Codex settings
  (`allow_managed_hooks_only` in `requirements.toml`), which can switch
  project hooks off.
- A determined agent running as your user can get around the guard, for
  example with a script it writes and runs. See [threat coverage](../threats.md).
- Limits of each pack are listed on its page, for example
  [core.secrets](../packs/core.secrets.md#not-covered) and
  [core.self](../packs/core.self.md#not-covered).

## Not yet verified live

saiife's Codex support is built from Codex's docs and source code. It has not
yet been run against a live Codex install. Still to check:

- The `/hooks` trust step, as described above.
- That Codex loads hooks from the project's `.codex/config.toml`.
- That `apply_patch` sends the patch text in `tool_input.command`.
- Where company-managed settings live (`requirements.toml`, likely in
  `/etc/codex/`), so `status` can check them.
- The `CODEX_HOME` setting, which saiife's rules use for Codex's own folder.
  It comes from product docs, not from our research.
- Very large tool inputs (over 1 MiB): saiife should still find every file
  path in them. We have not checked this on a live install.
