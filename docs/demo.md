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

One exception: when the script builds saiife itself (no `SAIIFE_BIN`),
`cargo` uses your real `~/.cargo` and `~/.rustup` (toolchain and crate
cache), as any `cargo build` does.

It also stops if a folder above the sandbox already has
`.saiife/config.toml`, since `saiife init` would act on that project
instead. Point `TMPDIR` somewhere else if that happens.

## Live check with real agents

`scripts/live-check-agents.sh` is the same idea with real Codex and Gemini
CLI sessions. It uses your own agent logins, so only you run it, never CI:

```sh
bash scripts/live-check-agents.sh --setup   # once: prints how to trust each test project
bash scripts/live-check-agents.sh
```

**How the agents run.** Gemini CLI runs with `--approval-mode yolo`: no
sandbox, every tool call is approved automatically and runs as you, with
access to your files. Codex runs with `exec --full-auto`: inside its
workspace-write sandbox (writes limited to the project folder and temp).
The prompt asks only for two harmless commands in a throwaway project, but
the model is not forced to stick to it. The script prints this warning and
asks you to type `yes` before starting any agent; `--yes` skips the
question (and is required when stdin is not a terminal).

For each agent on `PATH` it asks the agent to `cat .env` and to run
`saiife init --off`, then prints PASS or FAIL for each block (or
`SKIP <agent>: not installed`). The summary, with the agent versions, is
written to `~/.cache/saiife-live/result.txt`. It copies no credentials; the
test projects and its temporary audit log are deleted when it ends. Like the
demo, it refuses to run if a folder above `~/.cache/saiife-live` has
`.saiife/config.toml`.

If a check fails with no hook call recorded, either the test folder or hook
is not trusted yet (run `--setup`), or the agent does not pass saiife's
`SAIIFE_*` settings on to the hook, so the records went to your default
audit log (`saiife audit --agent codex` or `--agent gemini`).

## The locked demo (CI only)

`scripts/demo-locked.sh` is the five-minute end-to-end demo of locked mode.
It cannot be run on a normal machine: it installs a system service and
creates users, so it is a phase of `scripts/locked-linux/run.sh` and runs
only in the `locked-linux` CI job (the script refuses anywhere else). It
must finish in under 5 minutes; the job fails if it does not.

1. A `shop` generic `http` connector is set up against a tiny HTTPS mock on
   `127.0.0.1`. The mock's CA is copied, root-owned, to `/etc/saiife/ca`.
   There is no internet. The mock's credential is in the vault.
2. As the unprivileged agent user `agent-ci` it tries to remove the managed
   hook, to kill the daemon (by the unit's `MainPID` only) and to read the
   vault key. Each must fail. The attempts are written to
   `demo-attempts.txt` and the job log.
3. `saiife api shop orders.list` is allowed and prints JSON.
4. `saiife api shop products.update product_id=42 --body -` is pending
   (exit 3). `approver-ci` runs `saiife approve <id>`, then
   `saiife api result <id>` is done, and the mock saw the write exactly once.
5. `saiife audit verify` reports the chain intact.
6. `saiife audit --report` writes an HTML file with the connector and
   approvals sections. The report and the attempts are copied to the job's
   log directory.

The demo puts the system config, `policy.d/shop.toml`, `/etc/saiife/ca`, the
secret and the approver user back when it ends, also when it fails.
