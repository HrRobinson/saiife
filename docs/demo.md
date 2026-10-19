# Demo

`scripts/demo.sh` shows saiife working end to end. It installs the Claude
Code hook into a throwaway project and sends it three recorded Claude Code
tool calls. All three must be blocked. The demo itself takes a second or two
(plus the build, if it builds). CI runs it on every push.

## Run it

From the repository root:

```sh
bash scripts/demo.sh
```

This builds the release binary first (`cargo build --release`). To use a
binary you already have:

```sh
SAIIFE_BIN=target/release/saiife bash scripts/demo.sh
```

To look around afterwards (the project, its `.claude/settings.json`, the
audit log, the HTML report), keep the sandbox:

```sh
KEEP=1 bash scripts/demo.sh
```

It needs no network and no Claude Code install: the tool calls are recorded
payloads, sent to `saiife check` exactly as Claude Code would send them.

## What it does

1. Makes a sandbox folder with `mktemp -d` (under `$TMPDIR` if set).
2. Builds saiife, or uses `SAIIFE_BIN`, and puts it first on `PATH`.
3. Creates a project with a `.env` file, runs `saiife init --agent claude`
   and `saiife status`.
4. Sends three Claude Code `PreToolUse` calls through the hook command
   (`saiife check --hook-exit --agent claude`):
   - Bash `rm -rf ~`
   - Read `.env`
   - Bash `saiife init --off`
5. Shows `saiife audit`, then writes an HTML report with
   `saiife audit --report`.
6. Exits 0 only if all three calls were blocked (exit code 2) and the report
   was written.

## Expected output

The three verdict lines (the sandbox path differs on each run):

```
== three Claude Code tool calls through the hook
  Bash: rm -rf ~               blocked  BLOCKED by core.filesystem: recursive rm on a filesystem root, home, or system directory is catastrophic and irreversible
  Read: .env                   blocked  BLOCKED by core.secrets: `.env` files hold secrets (read: /tmp/tmp.XXXXXXXXXX/home/app/.env)
  Bash: saiife init --off      blocked  BLOCKED by core.self: an agent may not turn saiife off; run `saiife init --off` in your own terminal
```

and at the end:

```
OK: 3 of 3 calls blocked; report: /tmp/tmp.XXXXXXXXXX/report.html
```

Without `KEEP=1` the sandbox, report included, is deleted when the script
ends.

## It never touches your real home

Before anything else runs, the script points `HOME`, `SAIIFE_DATA_DIR`,
`SAIIFE_AUDIT_DIR` and the `XDG_*` folders into the sandbox, and stops if
`HOME` is not inside it. Your own `~/.claude`, saiife data and audit log are
never read or written. The sandbox is removed on exit, also when the script
fails.

## Live check with real agents

`scripts/live-check-agents.sh` is the same idea with real Codex and Gemini
CLI sessions. It uses your own agent logins, so only you run it, never CI:

```sh
bash scripts/live-check-agents.sh --setup   # once: prints how to trust each test project
bash scripts/live-check-agents.sh
```

For each agent on `PATH` it asks the agent to `cat .env` and to run
`saiife init --off`, then prints PASS or FAIL for each block (or
`SKIP <agent>: not installed`). The summary, with the agent versions, is
written to `~/.cache/saiife-live/result.txt`. It copies no credentials; the
test projects and its temporary audit log are deleted when it ends.
