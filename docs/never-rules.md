# Never-rules: your own packs

A never-rule is something you never want an agent to do on this machine:
`deploy-prod` from a laptop, a write under `~/billing`, a `terraform apply`
without a plan. saiife ships built-in packs for the common cases (see
[packs](packs/README.md)). A user pack is your own pack, in a file you write.
It is enforced by the same guard as the built-ins, in the same hook, and it
shows up in the audit log under its own id.

## User packs

### Where they live

One pack per file, `*.toml`, in a `policy.d/packs` directory:

| Mode | Directory |
| --- | --- |
| Locked mode (a root-owned install) | `/etc/saiife/policy.d/packs/` (next to `config.toml`) |
| Developer mode, Linux and macOS | `~/.config/saiife/broker/policy.d/packs/` |
| Developer mode, Windows | `%LOCALAPPDATA%\saiife\personal\policy.d\packs\` |

In locked mode root owns the directory (0755) and the files (0644), so the
agent cannot edit them, and `saiife doctor` checks it like `policy.d`. On
Windows the locked directory is `C:\ProgramData\saiife\etc\policy.d\packs`.
Packs are never read from a project: a repository cannot loosen or add
rules for you.

Limits, so the hook stays fast:

- at most 32 files, and 256 KiB of pack text in total;
- at most 128 rules in total across all user packs;
- a file name starting with a dot is skipped;
- a symlinked directory or file is refused.

### The file format

The pack id is `user.<slug>`: 1 to 48 characters of `a-z`, `0-9` and `-`, not
starting with `-`. A user pack is always on. `default_on = false` and
`lazy = true` are errors. Unknown keys are errors too, so a typo cannot
silently turn a rule off.

```toml
[pack]
id = "user.no-prod"           # required: user.<slug>
name = "Never prod"           # shown by `saiife packs`
description = "Production deploys are done by CI, not by an agent."
version = 1                   # optional, default 1
triggers = ["deploy-prod", "terraform"]   # see below
# windows_triggers = ["deploy-prod.exe"]  # extra triggers on Windows
# substitution_failsafe = true            # default true

# A command rule. `id` is required on every [[deny]].
[[deny]]
id = "deploy-prod"
pattern = '^deploy-prod\b'    # a regex, matched against each command
reason = "Production is deployed by CI only."
where = "everywhere"          # "host" or "everywhere" (default), see Boxes
ask = false                   # true: a request to approve, see below
# platform = "windows"        # only on Windows
# whole_segment, after_env_change, peeled_wrappers, no_redirections:
# the same matching options the built-in packs use

# A path rule: files read or written by file tools and shell commands.
[[deny_path]]
glob = "$HOME/billing/**"
access = "write"              # read | write | any | replace | content
reason = "Billing files are edited by hand only."
where = "everywhere"
# ancestors = true            # match the parents of the glob instead (write
#                             # rules, variable-rooted glob without wildcards)

# A carve-out inside this pack. It can never loosen a built-in pack.
[[allow]]
pattern = '^deploy-prod --dry-run\b'
reason = "A dry run changes nothing."
```

`triggers` is a list of words. A command rule is only looked at for a command
that contains one of them. A deny rule in a pack without `triggers` never
fires, so every user pack with a `[[deny]]` needs them.

`access` for a path rule: `read`, `write` (every write, a `chmod` included),
`any`, `replace` (a write that changes what the file holds) and `content`
(not read and not overwritten, but `chmod` is fine). Path variables such as
`$HOME` and `$PROJECT` (and `~`) are expanded the way the built-in packs
expand them.

A user pack can only add rules. An `[[allow]]` in it exempts a command from
that pack's own deny rules, never from a built-in's: `git reset --hard` stays
blocked whatever your pack says. A pack whose id does not start with `user.`
is an error.

Try a rule before relying on it:

```
saiife test "deploy-prod --now"        # exit 1 when a rule blocks it
saiife explain "deploy-prod --now"     # which pack and rule, and why
saiife packs                           # your packs are listed with DEFAULT "user"
saiife packs user.no-prod              # every rule of the pack
```

`saiife policy check <config>` compiles every user pack beside a locked
policy, for the host and for the box profile, and prints each error. Its
`ok:` line ends with `, N user packs)` when there are any.

### A broken pack

A user pack is a rule you asked for, so a pack that cannot be loaded is not
skipped quietly. What happens depends on the mode:

- **Locked mode: fail closed.** A file that cannot be read, a bad header, a
  duplicate id, a regex that does not compile, a bad glob, an unknown key or
  `where`, a file over the cap, a symlink: every hook call is denied with
  `user pack <file>: <why>`, and the audit log records `error_denied`. This is
  the same as a broken `config.toml`. Fix the file; the next call works.
- **Developer mode: the user packs go off, loudly.** Only the user packs are
  dropped: the built-in and project packs still judge the call, so a broken
  user pack never turns off `rm -rf /` or a secret read. stderr says
  `user pack <file>: <why> (not loaded); ... failing open (allow)`. A call the
  built-ins deny is a normal deny. A call they allow goes through and the
  audit log records `error_allowed` with the pack error as its reason. If
  `/etc/saiife` asks for fail closed, the call is denied instead.

A rule left out because of its `platform`, or because of the box profile, is
not an error.

### Asking instead of blocking: `ask`

`ask = true` on a `[[deny]]` (which needs an `id`) turns the block into a
request to approve:

- **Locked mode with approvers:** the call becomes a pending request in
  [approvals](approvals.md). An approver can allow that one call. The rule is
  added to `[guard] ask` as `user.<slug>/<id>` for you; you do not edit
  `config.toml`.
- **Developer mode:** there are no approvals, so it is a plain deny, and the
  reason ends with `(needs approval; approvals need locked mode)`.

## Boxes

Boxes are a planned use of user packs (see [dev environments](dev.md)). What
exists today is the box profile itself: `saiife explain --profile box
"<command>"` shows what a box would decide, and `saiife check --profile box`
judges with it (the policy hash records `profile box`). The boxes step will
write the hook that runs inside a box with this profile; until then no box
runs it.

Each rule says where it is in force with `where`:

- `where = "everywhere"` (the default): on the host and in boxes;
- `where = "host"`: on the host only. The box profile leaves the rule out
  when the pack loads, without a warning. Use it for a rule about something
  that only exists on the host, such as a path under your home directory.

Every built-in rule stays in the box profile. The developer policy hash
records `profile box` when the box profile is used, so an audit record shows
which profile judged a call.

What a user rule does inside a box is one of three things:

| Status | Which rules | What it means |
| --- | --- | --- |
| off in boxes (host only) | `where = "host"` | Not enforced in a box. |
| checked at diff review (planned) | a path rule with `where = "everywhere"` whose access covers writes (`write`, `any`, `replace`, `content`) | The box cannot stop the write. The design is that when the box's changes come back for review, a file such a rule forbids is flagged, and landing the changes needs your approval. The boxes step adds this; nothing flags files yet. |
| advisory in boxes | every command rule, and read-only path rules | Not enforced in a box. |

A rule shown as "advisory in boxes" is not enforced there. Do not count on it
to stop an agent inside a box. What a box does enforce comes from the box
itself: it has no network except through the gateway, it holds no secrets,
and pushing is protected. Those are not user rules, and a user rule does not
claim them.
