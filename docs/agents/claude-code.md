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
        "matcher": "Bash|Read|Grep|Glob|LS|Write|Edit|MultiEdit|NotebookEdit",
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
| `Bash` | a shell command | all packs that are on |
| `Read`, `Grep`, `Glob`, `LS` | a file read | [core.secrets](../packs/core.secrets.md) |
| `Write`, `Edit`, `MultiEdit`, `NotebookEdit` | a file change | [core.self](../packs/core.self.md) |

The timeout is 10 seconds. If saiife does not answer in time, or cannot
start, Claude Code runs the tool anyway (it "fails open"). This is on
purpose for v1, where a person is nearby: a broken guard should not stop your
work. When saiife itself hits an error, it allows the tool and records
`error_allowed` in the audit log.

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
