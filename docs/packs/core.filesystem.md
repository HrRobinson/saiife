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
- `cd / && rm -rf *` is allowed. The guard does not track `cd`, so it does not
  know the delete runs in the root folder.
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
allow rm -rf node_modules
allow rm -rf /tmp/scratch
allow rm file.txt
allow chmod -R 755 ./assets
```
