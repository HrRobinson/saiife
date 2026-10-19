# Core: git (core.git)

This pack stops git commands that throw away work for good: discarding
uncommitted changes, deleting untracked files, overwriting a shared branch,
or force-deleting a branch that was never merged.

## On by default

Yes. It is always on. It cannot be turned off in `.saiife/config.toml`: the
`packs` list there only adds opt-in packs.

## Blocked

- `git reset --hard` (except the rewind below). It discards all uncommitted
  changes, and they cannot be recovered.
- `git clean -f` (also `-fd`, `-xfd`). It permanently deletes untracked files.
- `git push --force` or `git push -f`. A force-push can overwrite the history
  of a shared branch.
- `git branch -D`. It force-deletes a branch even if it was never merged.
- `git checkout .` and `git checkout -- .`. They discard every unstaged change
  in the project at once.

## Allowed on purpose

- `git reset --hard HEAD~1` (any `HEAD~N`). This is a deliberate rewind, and
  git's reflog can bring the commits back.
- `git push --force-with-lease`. This is the safe force-push: it refuses when
  someone else has pushed in the meantime.
- `git branch -d` (lower-case). Git refuses to delete an unmerged branch.
- Everyday commands: `git status`, `git commit`, `git push`, `git diff`,
  `git checkout main`, `git clean -n` (a dry run).

## Not covered

- Other ways to lose uncommitted work are not judged, for example
  `git restore .`, `git stash drop` or `git checkout -- <file>`.
- `git push --force` to a branch name with a `+` prefix
  (`git push origin +main`) is not judged.
- Rewriting history with `git rebase` or `git filter-branch` is allowed.
- Reading a secret from git history (`git show HEAD:.env`) is a `core.secrets`
  topic and is not seen there either.

## Examples

```saiife-examples
deny git reset --hard
deny git reset --hard origin/main
deny git clean -fd
deny git push --force origin main
deny git push -f origin main
deny git branch -D feature
deny git checkout .
allow git reset --hard HEAD~1
allow git push --force-with-lease
allow git branch -d merged
allow git status
allow git clean -n
```
