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
  `cd "$(mktemp -d)"`, `cd $SOME_VAR`, `cd ~otheruser`, `popd`. The delete
  after it is judged as written, so `cd "$(...)" && rm -rf *` is allowed. A
  relative `cd` (`cd build`) is followed only from a folder saiife knows.
- `cd` is followed by its text alone. saiife does not check that the folder
  exists or follow symlinks, and it assumes the `cd` worked. A `cd` in a
  pipeline (`cd / | ...`) or in the background (`cd / &`) is not followed.
  Neither is a `cd` written as an `if` or `while` condition
  (`if cd /; then ...`).
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
allow rm -rf node_modules
allow rm -rf /tmp/scratch
allow rm file.txt
allow chmod -R 755 ./assets
allow cd /tmp && rm -rf ./build
allow cd build && rm -rf *
allow (cd / && ls) && rm -rf ./dist
allow cd "$(mktemp -d)" && rm -rf *
```
