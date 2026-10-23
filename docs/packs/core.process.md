# Core: process (core.process)

This pack stops an agent from killing processes without saying which one.
`pkill -n` kills the newest process on the machine, `pkill -o` the oldest,
`pkill -u me` every process you own, and `kill -9 -1` every process you may
signal. An agent that only wanted to stop its own dev server can take down
your desktop session this way. While saiife was being built, an agent ran
`pkill -n` and `pkill -o` and crashed its owner's machine.

## On by default

Yes. It is always on.

## Blocked

Commands are judged after the wrappers saiife sees through (`timeout 5`,
`setsid`, `nice -n 5`, `env`, `sudo`, `xargs` and the others listed in
[core.lock](core.lock.md#blocked)), so `timeout 5 pkill -n` is blocked like
`pkill -n`.

- `pkill` without a pattern but with a selector that picks processes by
  something other than their name: `-n`/`--newest`, `-o`/`--oldest`,
  `-u`/`--euid`, `-U`/`--uid`, `-g`/`--pgroup`, `-G`/`--group`,
  `-s`/`--session`, `-P`/`--parent`, `-t`/`--terminal`, `-O`/`--older`,
  `-r`/`--runstates`, `--cgroup`, `--ns` and `--env`. So `pkill -n`,
  `pkill -9 -o` and `pkill -u jonas` are blocked.
- `pkill --inverse`, which kills every process that does not match.
- A `pkill` or `killall -r` pattern that matches every name: `.`, `''`,
  `.*`, `^`, with or without `-f` (`pkill -f .`).
- `killall` without a process name, with `-u`/`--user` or `-Z`/`--context`
  (`killall -u jonas`).
- `killall5`, which signals every process on the machine.
- `kill` with the pid `-1` (every process you may signal), `0` or `-0`
  (your own process group, which holds the agent itself) or `1` (init):
  `kill -9 -1`, `kill -- -1`, `kill -s KILL -1`, `kill 0`, `kill 1`. Also
  written `+1`, `01` or `-1:<inode>`, and after another pid
  (`kill 1234 -1`).

Options are read the way the tools read them, from each tool's own option
list: long options can be shortened (`pkill --new`), short ones bundled
(`pkill -en`), and an option's value is not mistaken for a pattern
(`pkill -u jonas` has no pattern). A signal in front (`pkill -9 -n`,
`killall -KILL -u jonas`) does not hide the option.

## Allowed on purpose

- `kill` of a process id or a job: `kill 12345`, `kill -9 12345`,
  `kill %1`, `kill -- -12345` (the process group 12345), `kill -0 12345`
  (is it alive?), and `kill $(cat app.pid)`.
- `kill -1 12345` and `kill -0 12345`: the first `-1` or `-0` is the
  signal (HUP or the alive check), not a pid.
- Listing signals: `kill -l`, `kill -l 1`, `kill -L`, `killall -l`.
- `pkill` and `killall` with a process name or a pattern:
  `pkill node`, `pkill -f 'npm run dev'`, `pkill -n node` (the newest
  `node`), `pkill -u jonas node`, `killall -HUP nginx`,
  `killall -r '^node$'`.
- `pkill -F app.pid` and `pkill -p 12345`, which name their process.
- `pgrep` in every form, including `pgrep -n` and `pgrep -f .`: it only
  lists processes.

## Not covered

- A broad pattern that does not match every name: `pkill a`, `pkill -f /`
  or `pkill -f bin` still kill many processes. saiife blocks only patterns
  that match any name.
- A pid found at run time: `kill $(pgrep -n)`, `pgrep -o | xargs kill` or
  `kill -9 $PID` where the variable holds `-1`. Substitutions are not
  blocked here, because `kill $(cat app.pid)` is everyday use.
- `kill <name>` (util-linux `kill` can take a process name) and other tools
  that send signals to many processes: `skill`, `snice`, `systemctl kill`,
  `loginctl kill-user`, `fuser -k`.
- Code run through an interpreter: `python3 -c 'import os;
  os.kill(-1, 9)'`, `perl -e 'kill 9, -1'` and the like.

It also blocks too much in a few cases. This is the safe direction:

- A lone `kill -1` or `kill -0` (a signal with no pid; kill refuses it).
- A `pkill` word that may be a signal or a bundle of options is read both
  ways: `pkill -USR1` with nothing else is read as `-U SR1` too, and
  blocked (pkill itself would refuse it: no pattern).
- A `pkill` long option that pkill does not know (`pkill --frobnicate`)
  counts as a selector.
- A pattern saiife cannot read (`pkill 'a('`), longer than 256 characters,
  or behind more than 32 others counts as matching every name.
- An option value that happens to match every name (`pkill -t . node`).
- `xargs pkill -n` and the like: the pattern `xargs` would add at run time
  is not known, so the command counts as having none.

The limits that apply to every pack are in
[Limits of the guard as a whole](../threats.md#limits-of-the-guard-as-a-whole).

## Examples

```saiife-examples
deny pkill -n
deny pkill -o
deny pkill --newest
deny pkill -9 -o
deny timeout 5 pkill -n
deny setsid pkill -o
deny nice -n 5 pkill -n
deny env pkill -n
deny pkill -u jonas
deny pkill --euid jonas
deny pkill -G users
deny pkill -t pts/1
deny pkill --inverse node
deny pkill .
deny pkill ''
deny pkill -f .
deny killall -u jonas
deny killall -9 -u jonas
deny killall -r .
deny killall5
deny kill -9 -1
deny kill -- -1
deny kill -s KILL -1
deny kill 1234 -1
deny kill 0
deny kill -- -0
deny kill 1
deny kill -9 1
allow kill 12345
allow kill %1
allow kill -9 12345
allow kill -1 12345
allow kill -0 12345
allow kill -- -12345
allow kill -l
allow kill $(cat app.pid)
allow pkill node
allow pkill -f 'npm run dev'
allow pkill -n node
allow pkill -u jonas node
allow pkill -F app.pid
allow killall -HUP nginx
allow killall -r '^node$'
allow pgrep -a node
allow pgrep -n
```
