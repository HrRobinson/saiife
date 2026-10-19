# Core: self-protection (core.self)

This pack protects saiife itself. An agent may not turn saiife off, change
its settings, remove its hook from the agent's settings, replace the saiife
program, or hide or delete the audit log. Only you can make these changes,
in your own terminal.

## On by default

Yes. It is always on. It cannot be turned off in `.saiife/config.toml`: the
`packs` list there only adds opt-in packs.

## Blocked

**Commands:**

- `saiife init --off` run by an agent. Run it in your own terminal instead.
- An alias named `saiife` (`alias saiife=true`). It would replace the guard.
- Starting an agent (`claude`, `codex`, `gemini`) or saiife with a changed
  `PATH`, `HOME`, `XDG_DATA_HOME`, `CODEX_HOME`, `CLAUDE_CONFIG_DIR` or Gemini
  system settings path, for example `PATH=/tmp/fake:$PATH claude`. This can
  bypass the guard or hide the audit trail.
- Changing one of those settings earlier on the same command line, or running
  `eval` or `source` (whose effect saiife cannot see), and then starting an
  agent or saiife.
- Setting `SAIIFE_AUDIT_DIR` or `SAIIFE_DATA_DIR`. Moving these folders hides
  decisions from the audit trail.
- Starting Claude Code with its own settings (`claude --settings ...`,
  `--setting-sources`). That can leave the saiife hook out.
- Changing Codex's hook settings from the command line (`codex -c hooks...`,
  `-c features...`, `--enable`/`--disable` hooks).

**Files.** Writing, moving or deleting these is blocked, both through the
agent's file tools and through shell commands (`rm`, `mv`, `cp`, `sed -i`,
`tee`, `>`, `git rm`, `git checkout`):

- The `.saiife/` folder with the project config. Only you change it, with
  `saiife init`.
- The agent settings that hold the saiife hook: `.claude/settings.json`,
  `.claude/settings.local.json`, `.codex/config.toml`, `.gemini/settings.json`,
  in the project and in your home folder, and the `.claude`, `.codex` and
  `.gemini` folders themselves.
- saiife's audit folder, its data folder (audit trail and integrity records)
  and the saiife program, plus any parent folder of these.

## Allowed on purpose

- Reading saiife's files and settings. Only changes are blocked.
- Everyday saiife commands: `saiife status`, `saiife audit`, `saiife packs`,
  `saiife explain`.
- Starting an agent normally, for example `claude -p "fix the tests"` or
  `codex exec fix`.
- `saiife init --off` in your own terminal. That terminal is not hooked.

## Not covered

- `saiife init --off` in your own terminal works. That terminal is not hooked,
  so saiife does not judge it.
- A shell function named `saiife` is not detected (an alias is).
- `unset HOME`, `export -n HOME` or `declare +x PATH` before starting an agent
  are not treated as a change of setting.
- A program name built at run time is not judged, for example
  `$(echo saiife) init --off`.
- `codex --profile` can pick a user profile with other hook settings.
- `git stash` saves and resets the whole project, including saiife's files.
  It is not judged.
- `unset SAIIFE_AUDIT_DIR` is allowed. It only affects that one shell.
- A file name built at run time and hidden in `$(...)`, for example
  `cat $(ls)` or an escape-encoded name like `cat $(echo -e '.\x65nv')`, is
  skipped without a note. An escape-encoded name is a deliberate bypass.
- A plain `$PATH` hidden in a here-document or a comment can offset one
  disguised `$PATH` spelling elsewhere on the same line. This needs a
  deliberate attack.

It also blocks too much in a few cases. This is the safe direction:

- `eval` and `source` count as a change of setting, so an agent started after
  them on the same line is blocked: `eval "$(ssh-agent -s)"; claude ...`,
  `eval "$(direnv hook bash)" && codex ...`,
  `source venv/bin/activate; claude ...`. The agent can start the nested
  agent as a separate command.
- `export PATH=$PATH:./{a,b}` is blocked.
- `git restore --staged .claude/settings.json` is blocked.
- `rm -rf target` is blocked when the `saiife` program on `PATH` is a build
  inside that folder (this affects only people who build saiife).

### Limits of the guard as a whole

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

## Examples

```saiife-examples
deny saiife init --off
deny bash -c 'saiife init --off'
deny alias saiife=true
deny PATH=/tmp/fake:$PATH claude
deny HOME=/tmp/x claude -p hi
deny export SAIIFE_AUDIT_DIR=/tmp/x
deny claude --settings '{"disableAllHooks": true}' -p hi
deny codex -c features.hooks=false exec fix
deny source venv/bin/activate; claude -p hi
allow saiife status
allow saiife audit --blocked
allow claude -p "fix the tests"
allow codex exec fix
```
