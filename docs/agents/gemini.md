# saiife with Gemini CLI

Gemini CLI asks saiife before it uses a tool. saiife answers "block" or says
nothing (the tool runs). Every decision goes into the audit log.

## What `saiife init` writes

`saiife init` adds one hook entry to `.gemini/settings.json` in the project.
Everything else in that file stays as it was. If the file does not exist,
saiife creates it.

```json
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command|read_file|read_many_files|list_directory|glob|grep_search|write_file|replace",
        "hooks": [
          {
            "type": "command",
            "command": "saiife check --hook-exit --agent gemini",
            "name": "saiife",
            "timeout": 10000
          }
        ]
      }
    ]
  }
}
```

The timeout is in milliseconds (10 seconds), as Gemini CLI expects.

It also creates `.saiife/config.toml` (the packs that are on) and a record of
what it wrote, kept outside the project, so `saiife status` can notice
changes.

**One step left in Gemini CLI.** Gemini CLI only loads project hooks in a
trusted folder. Start `gemini` in the project folder and trust it when asked.
In an untrusted folder, the whole project settings file is ignored, so the
hook does not run.

## Which tools are judged

| Gemini CLI tool | Judged as | Main pack |
| --- | --- | --- |
| `run_shell_command` | a shell command | all packs that are on |
| `read_file`, `read_many_files`, `list_directory`, `glob`, `grep_search` | a file read | [core.secrets](../packs/core.secrets.md) |
| `write_file`, `replace` | a file change | [core.self](../packs/core.self.md) |

If saiife does not answer in time, Gemini CLI runs the tool anyway (it
"fails open"). When saiife itself hits an error, it allows the tool and
records `error_allowed` in the audit log. One case may work the other way;
see "If saiife is missing" below.

## If saiife is missing

If the `saiife` program is not on your `PATH` (moved, uninstalled), the shell
reports "command not found" (exit code 127). Gemini CLI's source suggests it
may then **block every tool** in the project, instead of letting them run.
This is not yet checked on a live install.

If Gemini CLI blocks everything after saiife was removed, either put
`saiife` back on your `PATH`, or remove the saiife entry (the
`saiife check` command) from `.gemini/settings.json` by hand.
`saiife status` reports a missing `saiife` as a failed check.

## Turning it off

Run `saiife init --off` in your own terminal, in the project folder. It
removes only the saiife entry from `.gemini/settings.json`. If saiife created
the file and nothing else is left in it, the file is deleted. An agent
cannot run `saiife init --off`: [core.self](../packs/core.self.md) blocks it.

## What `saiife status` checks

- The saiife entry in `.gemini/settings.json` is still there and unchanged.
- When Gemini CLI last called saiife in this project.
- For every agent: `.saiife/config.toml` is unchanged, and the `saiife` on
  your `PATH` is the same program, at the same version, that ran
  `saiife init`.

Each failed check prints what is wrong and how to fix it, and `status` exits
with code 1.

`status` does **not** check whether a Gemini CLI setting switches hooks off.
The name of that setting is not known yet (see below). Watch the "last hook
call" line: if it says "no call yet" after you used Gemini CLI, the hook is
not running.

## Not covered

- Other Gemini CLI tools are not sent to saiife: for example `web_fetch`,
  `google_web_search` and MCP tools.
- `read_many_files` with a broad pattern (`**/*`) relies on Gemini CLI's own
  handling of git-ignored files.
- Gemini CLI's `GEMINI_CLI_HOME` folder is not covered.
- Company-wide Gemini CLI settings (`/etc/gemini-cli/settings.json` on Linux)
  may take priority over the project file. Gemini CLI's docs and code disagree
  on this. `status` does not read them.
- A determined agent running as your user can get around the guard, for
  example with a script it writes and runs. See [threat coverage](../threats.md).
- Limits of each pack are listed on its page, for example
  [core.secrets](../packs/core.secrets.md#not-covered) and
  [core.self](../packs/core.self.md#not-covered).

## Not yet verified live

saiife's Gemini CLI support is built from Gemini CLI's docs and source code.
It has not yet been run against a live Gemini CLI install. Still to check:

- The hook entry's `name` field and the timeout in milliseconds.
- The folder trust step, as described above.
- Whether a missing `saiife` (exit code 127) blocks every tool (see
  "If saiife is missing").
- The Gemini CLI setting that switches hooks on or off, so `status` can
  check it.
- Very large tool inputs (over 1 MiB): saiife should still find every file
  path in them. We have not checked this on a live install.
