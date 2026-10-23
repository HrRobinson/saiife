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

Commands are judged after the wrappers saiife sees through, with their
options: `sudo`, `env`, `timeout`, `time`, `nice`, `nohup`, `setsid`,
`stdbuf`, `ionice`, `xargs`, `flock`, `chroot`, `command`, `builtin` and
`exec`. So `timeout 5 crontab -e` and `nice -n 5 sudo ls` are blocked like
`crontab -e` and `sudo ls`. Options are read the way the wrappers read
them, from each wrapper's own option list: a shortened long option counts
too (`nice --adj 5`, `flock --wai 5`), short options can be bundled
(`xargs -0a FILE`), and `--` ends the options (`nohup -- sudo ls`). The
same goes for the file `xargs -a` reads (`xargs --arg FILE` reading the
audit signing key is blocked), for `pkill -f` (`--f`, `--ful`, `-9f`, or
`-f` after the pattern) and for `killall -r` (`--reg`, `-Ir`, `-regexp`).
A signal word in front (`pkill -IO -f`, `killall -XFSZ -r`) does not hide
the option. The command in
`env -S '...'` is judged as a command of its own. An `env -S` string with
env's own escapes (`\_`, `\c`), a `${NAME}` or a `#` is blocked outright:
saiife does not read those.

**Commands:**

- Changing privileges: `sudo` anywhere in front of a command, and a bare
  `sudo` or `sudo -l`; `su`, `doas`, `pkexec` and `run0`; `osascript` with
  `with administrator privileges`.
- saiife's service: `systemctl`, `kill`, `pkill` or `killall` with an
  argument that names saiife (`saiifed`, `saiife*`, `-u saiife`, or a short
  prefix like `sai` or `saii*`), and `launchctl` with a `com.saiife.`
  service. A pattern that matches `saiifed` without spelling it is blocked
  too: a regular expression for `pkill` or `killall -r` (`pkill 'sa.*fed'`),
  and a glob for `killall` or `systemctl` (`systemctl stop '*fed'`). A
  `pkill -f` pattern is also matched against the daemon's whole command
  line, `/opt/saiife/bin/saiife daemon --system`.
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
  `is-failed`, `cat`, `list-units` and `list-unit-files` of saiifed or of
  any pattern (`systemctl list-units '*'`), `crontab -l`, `at -l` and
  `atq`. A wrapper in front of them (`sudo crontab -l`) is still blocked.
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
- Launchers saiife does not see through: `taskset`, `chrt`, `unshare`,
  `prlimit`, `find ... -exec`, `tmux` and `screen`, `parallel`,
  `ssh localhost`, `script -c`, `sg ... -c` and `flock ... -c`, and a program path found
  at run time (`$(which sudo) ls`). Without root a privilege change fails
  on permissions anyway.
- Other files under `~/.config/systemd/` than the unit folders, such as
  `user.conf`, which sets defaults for the user's service manager.
- A service or process named some other way: `kill 1234` where 1234 is
  saiifed's process id, a name built at run time
  (`systemctl stop $(echo saiifed)`), or a `pkill -f` pattern that matches
  only saiifed's process in another way. Substitutions are not blocked
  here, because `kill $(cat app.pid)` is everyday use.
- Broad `pkill` and `killall` selectors: `-u` or `-U` with another user
  than saiife, `-g`, `-P` and `-s`. saiifed runs as its own user, so without
  root the kernel refuses the signal anyway.
- An option of a wrapper that saiife does not know (`nice --frobnicate`).
  The command after it may not be judged, so saiife records the call as
  not fully judged. In locked mode that blocks it.
- Other ways to run code later as the user: a shell profile (`~/.bashrc`),
  a git hook, `nohup ... &` or a `tmux` session. Every agent call from them
  still goes through saiife.
- In locked mode the hook runs with a cleared environment, so
  `$XDG_CONFIG_HOME` is always `~/.config` there. A unit dir set through
  another variable is not known.

It also blocks too much in a few cases. This is the safe direction:

- A `pkill`, `killall` or `systemctl` pattern with a variable in it
  (`pkill "$APP"`, `pkill "sa${X}fed"`) counts as matching saiifed: what
  it expands to is not known. Write the name instead.
- Any `systemctl` naming saiife other than the read-only queries above, and
  any read-only query with a wrapper or an option before the verb other
  than `--no-pager`, `--user`, `--system`, `--full`, `--no-legend`,
  `--quiet`, `-l` or `-q`. Use `saiife status` instead.
- `crontab` and `at` with anything but `-l`, and any `sudo`, even one that
  would only list rights (`sudo -l`).
- A `pkill` or `killall -r` pattern that matches `saiifed` along with other
  names, such as `pkill d`, and a pattern saiife cannot read (`pkill 'a('`).
  With `pkill -f`, any part of the daemon's command line counts, so
  `pkill -f bin`, `pkill -f daemon` and `pkill -f system` are blocked.
- A `systemctl` or `killall` glob with a `\` (also systemd's own escapes,
  such as `\x2d`) or a class like `[[:alpha:]]`, outside the read-only
  queries: saiife does not read these.
- A pattern longer than 256 characters, and more than 32 pattern operands
  on one command (`systemctl restart` with 33 globs). Patterns are read
  without Unicode classes, and a pattern too large to compile counts as a
  match. Once one command line has spent 5 ms compiling patterns, every
  further pattern counts as a match, so a line full of costly patterns is
  blocked rather than left unjudged.
- A `pkill` long option that pkill does not know or cannot tell apart
  (`pkill --e`) counts as `-f`. An option value that starts with `-` is
  also read as options, so `pkill -u -f x` counts as `-f`.
- `killall` reads `-word` both as a long option (it uses
  `getopt_long_only`, so `-regexp` is `--regexp`) and as short letters,
  so a word that holds an `r` counts as `-r`: `killall -verbose x` is read
  as `-r` too.
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
deny nice -n5 sudo ls
deny setsid crontab /tmp/c
deny env -S 'sudo ls'
deny env -S 'sudo\_ls'
deny nice --adj 5 sudo ls
deny pkill -f 'bin/saiife daemon'
deny pkill --f 'opt/s.*e'
deny killall --reg '^sai'
deny pkill -IO -f 'opt/s.*e'
deny killall -XFSZ -r '^sai'
allow pkill -TERM node
deny flock --wai 5 /tmp/l crontab /tmp/c
deny flock --wait 5 /tmp/l sudo ls
deny nohup -- sudo ls
deny pkill 'sa.*fed'
deny systemctl stop '*fed'
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
allow pkill -f sain
allow flock --fcntl /tmp/l make
allow systemctl restart saint
allow env -S 'ls -la'
allow env -S 'node --inspect' app.js
allow systemctl list-units '*'
allow kill 1234
allow atop
allow cat /etc/codex/requirements.toml
```
