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
`pkill -n`. Redirections are not arguments: `pkill -n 2>/dev/null` is
blocked like `pkill -n`, and in `kill 1234 2>&1` the `1` is not a pid.

- `pkill` without a pattern but with a selector that picks processes by
  something other than their name: `-n`/`--newest`, `-o`/`--oldest`,
  `-u`/`--euid`, `-U`/`--uid`, `-g`/`--pgroup`, `-G`/`--group`,
  `-s`/`--session`, `-P`/`--parent`, `-t`/`--terminal`, `-O`/`--older`,
  `-r`/`--runstates`, `--cgroup`, `--ns` and `--env`. So `pkill -n`,
  `pkill -9 -o` and `pkill -u jonas` are blocked. A parent, process group
  or session given as literal ids above 1, or `$$`, names a target and is
  allowed (`pkill -P 1234`, `pkill -g $$`); `0` (pkill's own group or
  session, which holds the agent), `1` (init) and a value from a variable
  (`pkill -P $PID`) are not, nor is an option given twice
  (`pkill -P 1234 -P ''`: the last one counts).
- `pkill --inverse`, which kills every process that does not match.
- A `pkill` or `killall -r` pattern that matches most processes: one that
  matches at least 80% of a list of about 70 common process names (`.`,
  `''`, `.*`, `^`, `[a-z]`), a pattern of one character (`pkill e`,
  `pkill -f /`), and with `pkill -f` one that matches at least 80% of a
  list of common command lines. A pattern after `--` counts too, even when
  it starts with `-` (`pkill -- '-*.'`).
- A `pkill` or `killall` pattern or name built at run time:
  `pkill $(cat name.txt)`, `pkill -f "$(...)"`, `killall $(cat names)`,
  and one that is only a variable: `pkill "$NAME"`, `pkill -f "${X}"`,
  `killall -r "$X"`. It may come out empty, and an empty pattern matches
  every process.
- `killall` without a process name, with `-u`/`--user` or `-Z`/`--context`
  (`killall -u jonas`).
- `killall5`, which signals every process on the machine.
- `kill` with the pid `-1` (every process you may signal), `0` or `-0`
  (your own process group, which holds the agent itself) or `1` (init):
  `kill -9 -1`, `kill -- -1`, `kill -s KILL -1`, `kill 0`, `kill 1`. Also
  written `+1`, `01` or `-1:<inode>`, and after another pid
  (`kill 1234 -1`).
- `kill` with a pid computed by arithmetic: `kill -9 $((-1))`,
  `kill $((PID-1))`. It may come out as -1, 0 or 1.

Options are read the way the tools read them, from each tool's own option
list: long options can be shortened (`pkill --new`), short ones bundled
(`pkill -en`), and an option's value is not mistaken for a pattern
(`pkill -u jonas` has no pattern; in `pkill --signal 9 node`,
`pkill -u 0 node` and `killall -r -s 9 '^node$'` the pattern is the last
word). A signal in front (`pkill -9 -n`, `killall -KILL -u jonas`) does not
hide the option: only the first word can be a signal, and it is read both
as the signal and as options.

## Allowed on purpose

- `kill` of a process id or a job: `kill 12345`, `kill -9 12345`,
  `kill %1`, `kill -- -12345` (the process group 12345), `kill -0 12345`
  (is it alive?), `kill $PID`, `kill $(cat app.pid)`, `kill $(pgrep node)`
  and `kill $(lsof -ti:3000)`, with or without `2>/dev/null`, `2>&1` or
  `|| true` after them.
- `kill -1 12345` and `kill -0 12345`: the first `-1` or `-0` is the
  signal (HUP or the alive check), not a pid.
- Listing signals: `kill -l`, `kill -l 1`, `kill -L`, `killall -l`.
- `pkill` and `killall` with a process name or a pattern:
  `pkill node`, `pkill -f 'npm run dev'`, `pkill -n node` (the newest
  `node`), `pkill -u jonas node`, `killall -HUP nginx`,
  `killall -r '^node$'`. A pattern of two characters is allowed
  (`pkill sh`), even though it may match several processes.
- `pkill -F app.pid` and `pkill -p 12345`, which name their process.
- `pkill -P 1234` (the children of 1234), `pkill -P $$` (the children of
  the agent's shell), `pkill -g 1234` and `pkill -s 1234`.
- `pgrep` in every form, including `pgrep -n` and `pgrep -f .`: it only
  lists processes.

## Not covered

- A pattern that matches many processes, but fewer than 80% of saiife's
  list: `pkill sh`, `pkill -f bin` or `pkill -f /usr` still kill many
  processes. The list holds common names; a machine's own processes may
  differ.
- A pid found at run time other than by arithmetic: `kill $(pgrep -n)`,
  `pgrep -o | xargs kill`, or `kill -9 $PID` where the variable holds
  `-1`. These are not blocked, because `kill $(cat app.pid)` and
  `kill $PID` are everyday use.
- Launchers saiife does not see through: `chrt`, `taskset`, `unshare`,
  `script -c`, `find ... -exec`, `parallel`, `sg ... -c` and the like run
  `pkill -n` without the guard reading it.
- A pattern that is part variable, part text (`pkill "$X-server"`) is
  judged as its text alone (`-server`), since the variable may be empty.
  So `pkill "x$X"` and `killall "${X}d"` (one character left) are blocked,
  `pkill "${X}node"` is not.
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
- A pattern with a regex class set operation (`[a-z&&[^x]]`, `--`, `~~`
  inside `[...]`): pkill's and killall's regexes have none, so saiife does
  not try to read it.
- A leading signal name is also read in lower case as options:
  `pkill -TERM` alone is read as `-t erm` too (pkill would refuse it: no
  pattern).
- `xargs pkill -n` and `xargs kill -1` and the like: what `xargs` adds at
  run time is not known, so `pkill -n` has no pattern and `kill -1` no pid.
- A substitution in an option value counts like a pattern:
  `pkill -u $(whoami) node` is blocked. Write the user name instead.

The limits that apply to every pack are in
[Limits of the guard as a whole](../threats.md#limits-of-the-guard-as-a-whole).

## Examples

```saiife-examples
deny pkill -n
deny pkill -o
deny pkill -n 2>/dev/null
deny pkill -o 2>/dev/null || true
deny pkill -n &>/dev/null
deny pkill e
deny pkill '[a-z]'
deny pkill -- '-*.'
deny pkill $(cat name.txt)
deny pkill "$NAME"
deny pkill -P 1
deny kill -9 $((-1))
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
allow kill 1234 2>&1
allow kill -9 $PID >/dev/null 2>&1
allow kill $(cat .pid) 2>&1 || true
allow kill $(pgrep node)
allow pkill sh
allow pkill node
allow pkill -f 'npm run dev'
allow pkill -n node
allow pkill -u jonas node
allow pkill --signal 9 node
allow pkill -u 0 node
allow pkill -P 1234
allow pkill -P $$
allow pkill -F app.pid
allow killall -HUP nginx
allow killall -r '^node$'
allow pgrep -a node
allow pgrep -n
```
