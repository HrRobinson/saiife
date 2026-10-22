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

Commands are judged after the wrappers saiife sees through: `sudo`, `env`,
`timeout`, `time`, `nice`, `nohup`, `stdbuf`, `ionice`, `xargs`, `flock`,
`chroot`, `command`, `builtin` and `exec`. So `timeout 5 crontab -e` is
blocked like `crontab -e`.

**Commands:**

- Changing privileges: `sudo` anywhere in front of a command, and a bare
  `sudo` or `sudo -l`; `su`, `doas`, `pkexec` and `run0`; `osascript` with
  `with administrator privileges`.
- saiife's service: `systemctl`, `kill`, `pkill` or `killall` with an
  argument that names saiife (`saiifed`, `saiife*`, `-u saiife`, or a short
  prefix like `sai` or `saii*`), and `launchctl` with a `com.saiife.`
  service.
- Jobs that run later with no hook around them: `crontab`, `at`, `batch`,
  `systemd-run --user`, `launchctl load` and `launchctl bootstrap`,
  `loginctl enable-linger`, and `systemctl --user` with `link`, `enable`,
  `reenable`, `edit`, `daemon-reload`, `preset`, `preset-all`, `revert`,
  `add-wants`, `add-requires`, `set-property`, `set-environment` or
  `import-environment`.
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
- The managed agent settings: `/etc/claude-code` with
  `managed-settings.d/` and `managed-settings.json`,
  `/etc/codex/requirements.toml`, `/etc/gemini-cli/settings.json`, and the
  `/etc/codex` and `/etc/gemini-cli` folders.
- User services and autostart entries: `systemd/user/`,
  `systemd/user.control/` and `autostart/` under `~/.config` (and under
  `$XDG_CONFIG_HOME`, when it is set), `~/.local/share/systemd/user/`,
  `/run/user/<uid>/systemd/` and `~/Library/LaunchAgents/`, plus any parent
  folder of these (so `mv /tmp/s ~/.config/systemd` and
  `mv ~/.config ~/.config.bak` are blocked).

## Allowed on purpose

- Reading saiife's config, the audit log, the unit and the managed agent
  settings. Only changes are blocked (except for `/var/lib/saiife`).
- Read-only queries: `systemctl status`, `show`, `is-active`, `is-enabled`,
  `is-failed` and `cat` of saiifed, `crontab -l`, `at -l` and `atq`. A
  wrapper in front of them (`sudo crontab -l`) is still blocked.
- `systemctl` for other services, for example `systemctl status nginx`,
  and `systemctl --user start` or `restart` of an existing user service.
- `kill` and `pkill` of other processes, for example `kill 1234`.
- Commands that only start with the same letters, such as `atop`, `sudoku`
  or `suspend-test`, and words like `sudo` in an argument (`echo sudo`).
- `launchctl list`.

## Not covered

- Code run through an interpreter: `python3 -c 'import os;
  os.system("crontab x")'`, `perl -e`, `node -e`, `ruby -e` and the like.
  The guard does not read inside these programs. A script the agent writes
  and then runs is the same. The file permissions of a locked install stop
  them from writing saiife's files, and every agent call from them still
  goes through saiife.
- A wrapper saiife does not see through, for example `setsid sudo ls`,
  `script -c 'sudo ls'` or `flock /tmp/l -c 'sudo ls'`. Without root it
  fails on permissions anyway.
- A service or process named some other way: `kill 1234` where 1234 is
  saiifed's process id, a name built at run time
  (`systemctl stop $(echo saiifed)`), or a `pkill`/`killall` regular
  expression that matches saiifed without spelling `sai` (`pkill -f 'i+fed'`).
  Substitutions are not blocked here, because `kill $(cat app.pid)` is
  everyday use.
- Other ways to run code later as the user: a shell profile (`~/.bashrc`),
  a git hook, `nohup ... &` or a `tmux` session. Every agent call from them
  still goes through saiife.
- In locked mode the hook runs with a cleared environment, so
  `$XDG_CONFIG_HOME` is always `~/.config` there. A unit dir set through
  another variable is not known.

It also blocks too much in a few cases. This is the safe direction:

- Any `systemctl` naming saiife other than the read-only queries above, and
  any read-only query with a wrapper or an option before the verb other
  than `--no-pager`, `--user`, `--system`, `--full`, `--no-legend`,
  `--quiet`, `-l` or `-q`. Use `saiife status` instead.
- `crontab` and `at` with anything but `-l`, and any `sudo`, even one that
  would only list rights (`sudo -l`).
- Creating `~/.config/systemd` or moving `~/.config`, since they are
  parents of the user service folder.

The limits that apply to every pack are in
[Limits of the guard as a whole](../threats.md#limits-of-the-guard-as-a-whole).

## Examples

```saiife-examples
deny sudo ls
deny timeout 5 sudo ls
deny xargs sudo ls
deny env -u FOO sudo ls
deny su -
deny pkexec bash
deny systemctl stop saiifed
deny timeout 5 systemctl stop saiifed
deny pkill -u saiife
deny crontab -e
deny xargs crontab < /tmp/c
deny echo x | at now
deny systemd-run --user sh
deny systemctl --user enable --now x
deny loginctl enable-linger
deny codex --dangerously-bypass-hook-trust
deny GEMINI_CLI_SYSTEM_SETTINGS_PATH=/tmp/s gemini
deny rm -rf /etc/codex
deny mv /etc/claude-code /tmp/x
deny echo '{}' > /etc/claude-code/managed-settings.json
allow systemctl status nginx
allow systemctl status saiifed
allow crontab -l
allow atq
allow kill 1234
allow atop
allow cat /etc/codex/requirements.toml
```
