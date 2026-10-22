# Core: lock (core.lock)

This pack protects a locked saiife install from the agent. An agent may not
become root, stop or change saiife's service, set up jobs that run later
outside any agent session, turn off an agent's safety switches, or change
saiife's system files and the managed agent settings. Most of these would
fail on permissions anyway, but a clear block stops an agent from trying
again and again.

## On by default

On in locked mode (`locked = true` in `/etc/saiife/config.toml`), and it
cannot be turned off there. Elsewhere it is opt-in: `saiife init --pack
core.lock` in your own terminal turns it on for a project.

## Blocked

**Commands:**

- Changing privileges: `sudo`, `su`, `doas`, `pkexec` and `run0` as the
  command, also after `env`, `nohup`, `exec` or a `NAME=value` in front.
  `osascript` with `with administrator privileges`.
- saiife's service: `systemctl` with any argument that names `saiifed`
  (`systemctl stop saiifed`), `launchctl` with a `com.saiife.` service, and
  `kill`, `pkill` or `killall` naming `saiifed`.
- Jobs that run later with no hook around them: `crontab`, `at`,
  `systemd-run --user`, `launchctl load` and `launchctl bootstrap`.
- Agent safety switches: `--dangerously-bypass-hook-trust` anywhere in a
  command, and setting `GEMINI_CLI_SYSTEM_SETTINGS_PATH` or
  `GEMINI_CLI_SYSTEM_DEFAULTS_PATH`.

**Files.** Writing, moving or deleting these is blocked, both through the
agent's file tools and through shell commands:

- saiife's system files: `/etc/saiife`, `/opt/saiife`, `/var/log/saiife`,
  the audit folder, `/run/saiife` and `/etc/systemd/system/saiifed.service`,
  plus any parent folder of these (so `mv /etc /tmp/x` is blocked too).
- `/var/lib/saiife`, which holds the audit signing key. Reading it is
  blocked as well.
- The managed agent settings: `/etc/claude-code/managed-settings.d/` and
  `/etc/claude-code/managed-settings.json`, `/etc/codex/requirements.toml`,
  `/etc/gemini-cli/settings.json`, and the `/etc/codex` and
  `/etc/gemini-cli` folders.
- User services and autostart entries: `~/.config/systemd/user/`,
  `~/Library/LaunchAgents/`, `~/.config/autostart/`.

## Allowed on purpose

- Reading saiife's config, the audit log, the unit and the managed agent
  settings. Only changes are blocked (except for `/var/lib/saiife`).
- `systemctl` for other services, for example `systemctl status nginx`.
- `kill` and `pkill` of other processes, for example `kill 1234`.
- Commands that only start with the same letters, such as `atop`, `sudoku`
  or `suspend-test`, and words like `sudo` in an argument (`echo sudo`).
- `launchctl list`.

## Not covered

- A privilege change hidden behind a wrapper other than `env`, `command`,
  `nohup`, `exec`, `nice` or `setsid`, for example `timeout 5 sudo ls` or
  `xargs sudo`. Without root it fails on permissions anyway.
- A service or process name built at run time, for example
  `systemctl stop $(echo saiifed)` or `kill $(pgrep saiifed)`. Substitutions
  are not blocked here, because `kill $(cat app.pid)` is everyday use.
- Other ways to run code later: a shell profile (`~/.bashrc`), a git hook,
  `nohup ... &` or a `tmux` session. These run as the user, and every agent
  call from them still goes through saiife.
- A script the agent writes and runs can still try these changes. The file
  permissions of a locked install stop it from writing saiife's files.

It also blocks too much in a few cases. This is the safe direction:

- `systemctl status saiifed` is blocked, like any `systemctl` that names
  `saiifed`. Use `saiife status` instead.
- `crontab -l` and `at -l` are blocked, like any `crontab` or `at`.
- Any `sudo` is blocked, even one that would only list rights (`sudo -l`).

The limits that apply to every pack are in
[Limits of the guard as a whole](../threats.md#limits-of-the-guard-as-a-whole).

## Examples

```saiife-examples
deny sudo ls
deny su -
deny pkexec bash
deny systemctl stop saiifed
deny pkill saiifed
deny crontab -e
deny echo x | at now
deny systemd-run --user sh
deny codex --dangerously-bypass-hook-trust
deny GEMINI_CLI_SYSTEM_SETTINGS_PATH=/tmp/s gemini
deny rm -rf /etc/codex
deny echo '{}' > /etc/claude-code/managed-settings.json
allow systemctl status nginx
allow kill 1234
allow atop
allow cat /etc/codex/requirements.toml
```
