# Core: filesystem (core.filesystem)

This pack stops the few commands that can wreck a whole computer in one go:
deleting the whole disk, the home folder or a system folder, writing over a
raw disk, or formatting a disk. It does not judge ordinary deletes inside a
project. Anything it does not match is allowed.

## On by default

Yes. It is always on. It cannot be turned off in `.saiife/config.toml`: the
`packs` list there only adds opt-in packs.

## Blocked

- A recursive delete (`rm -r`, `rm -rf`, `rm --recursive`) of the root folder
  `/`, the home folder (`~`, `$HOME`) or a top-level system folder such as
  `/etc`, `/usr`, `/var`, `/home`, `/Users` or `/Library`. Recursive rm on
  these folders is catastrophic and cannot be undone.
- `rm --no-preserve-root`. This option exists only to defeat the root-delete
  safety check.
- `dd` writing to a disk device (`of=/dev/...`). It overwrites the raw disk.
- `mkfs` in any form. It formats a disk and erases everything on it.
- `truncate` on a disk device, and redirecting output onto a raw disk
  (`> /dev/sda`). Both corrupt the disk.
- A recursive `chmod` or `chown` on the root folder or a system folder. It
  breaks the system's permissions or ownership.
- An `rm` whose target is hidden inside `$(...)` (for example
  `rm -rf $(cat list.txt)`). saiife cannot see the target, so it blocks.
- A delete that lands on one of these folders because of an earlier `cd` on
  the same line: `cd / && rm -rf *`, `cd ~ && rm -rf .*`,
  `cd /usr && cd .. && rm -rf *`. saiife follows `cd` and `pushd` to `/`, `~`,
  `$HOME` or another absolute folder, and relative `cd`s from there (`..`
  included). The relative targets of `rm`, `chmod -R` and `chown -R` are
  judged as if they were written from that folder. A `cd` inside `( ... )`
  ends at the `)`.
- A `cd` may fail or be skipped, so it usually adds a folder instead of
  replacing one. The delete is then judged against every folder the shell
  may be in, so `cd /; cd /missing; rm -rf *` and
  `cd / || cd /tmp; rm -rf *` are blocked. A `cd` replaces the folder only
  for what runs when it worked: the commands after `cd X &&`, and the body
  of `if cd X; then ...` or `while cd X; do ...`. A `cd` inside an `if`
  body, a loop, a `case` branch, a function definition or a group after
  `&&`/`||` only adds. A `cd` after `!`, `time` or `time -p`, a `cd` used as
  a condition, and a `cd` run through `eval` are followed too.
- An `rm`, `chmod` or `chown` with a relative target on a line whose `cd`s
  leave more than 16 possible folders. saiife cannot judge it against all of
  them, so it blocks ("too many possible working directories to judge
  safely"). A line without such a command is judged as before.

These rules also apply when the command runs through `sudo`, `bash -c '...'`
or after `cd`.

## Allowed on purpose

- Deleting build output, caches and temporary files: `rm -rf node_modules`,
  `rm -rf ./build`, `rm -rf /tmp/scratch`.
- Deleting a single file or a folder inside the project: `rm file.txt`,
  `rm -r somedir`.
- `dd` into an ordinary file, `chmod` and `chown` on project files.

## Not covered

- Deleting your project's own folders (`rm -rf src`) is allowed. Git, backups
  and your review are the protection here.
- Only `rm`, `dd`, `mkfs`, `truncate`, `chmod`, `chown` and writes to
  `/dev/...` are judged. Other ways to delete files, such as
  `find ... -delete` or a script the agent writes and then runs, are not seen
  by this pack.
- A deep folder under a system folder is not treated as catastrophic. For
  example `rm -rf /var/folders/xy/tmp` is allowed.
- A `cd` to a folder saiife cannot work out is not followed: `cd -`,
  `cd "$(mktemp -d)"`, `cd $SOME_VAR`, `cd ~otheruser` (another user's home),
  `popd`. The delete after it is judged as written, so
  `cd "$(...)" && rm -rf *` is allowed. A relative `cd` (`cd build`) is
  followed only from a folder saiife knows.
- `CDPATH` is ignored. With `CDPATH` set, `cd usr` may go to `/usr`, but
  saiife treats it as a relative `cd` from the current folder.
- `cd` is followed by its text alone. saiife does not check that the folder
  exists or follow symlinks. A `cd` in a pipeline (`cd / | ...`) or in the
  background (`cd / &`) is not followed, since it runs in a shell of its own.
- Because a `cd` that is not followed by `&&` may have failed, the folder
  the line started in stays possible: run from your home folder,
  `cd proj; rm -rf *` is blocked (if `proj` is missing it would empty your
  home). Write `cd proj && rm -rf *` instead.
- A quoted `*` after a `cd` is read as a glob: `cd /usr && rm -rf "*"` is
  blocked, although it would delete only a file named `*`.
- Protection of saiife's own files is in the `core.self` pack, not here.

## Examples

```saiife-examples
deny rm -rf /
deny rm -rf ~
deny sudo rm -rf /etc
deny rm --recursive --force /var
deny dd if=/dev/zero of=/dev/sda
deny mkfs.ext4 /dev/sdb
deny chmod -R 777 /
deny rm -rf $(cat /tmp/list)
deny cd / && rm -rf *
deny cd ~ && rm -rf *
deny cd ~ || exit; rm -rf .*
deny (cd / && rm -rf *)
deny bash -c 'cd / && rm -rf *'
deny cd /usr && cd .. && rm -rf *
deny cd / || cd /tmp; rm -rf *
deny cd /; false && cd /tmp; rm -rf *
deny if cd /; then rm -rf *; fi
deny while cd /; do rm -rf *; done
deny ! cd /; rm -rf *
deny eval cd /; rm -rf *
deny cd /; cd /nonexistent; rm -rf *
deny cd /; cd /a || cd /b; rm -rf *
deny cd /; { cd /tmp; } || true; rm -rf *
deny cd /; f() { cd /tmp; }; rm -rf *
deny cd /; function f { cd /tmp; }; rm -rf *
deny time if cd /; then rm -rf *; fi
deny time -p cd / && rm -rf *
deny true && cd /a; true && cd /b; true && cd /c; true && cd /d; true && cd /e; true && cd /f; true && cd /g; true && cd /h; true && cd /i; true && cd /j; true && cd /k; true && cd /l; true && cd /m; true && cd /n; true && cd /o; true && cd /p; cd /etc; rm -rf *
deny chmod -R 777 /*
deny cd / && chmod -R 777 *
deny cd / && chown -R root *
allow rm -rf node_modules
allow rm -rf /tmp/scratch
allow rm file.txt
allow chmod -R 755 ./assets
allow cd /tmp && rm -rf ./build
allow cd build && rm -rf *
allow (cd / && ls) && rm -rf ./dist
allow cd "$(mktemp -d)" && rm -rf *
allow cd /tmp || exit; rm -rf *
allow if cd build; then rm -rf *; fi
allow cd /tmp && rm -rf *
allow cd /tmp; rm -rf *
```
