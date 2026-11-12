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

In developer mode the personal broker reads the same directory
(`<broker dir>/policy.d/packs`) when it starts and when it reloads. It checks
only each file's header there, and a header error (a bad or duplicate pack id,
a symlink, more files or bytes than the limits below) stops the broker from
starting or reloading until you fix the file.

After you add or edit a pack in locked mode, run `saiife policy reload`. The
hook reads the files on every call, but the daemon keeps the policy it loaded:
until the reload it does not know a new `ask = true` rule and refuses the
approval requests it makes.

Limits, so the hook stays fast:

- at most 32 files, and 256 KiB of pack text in total;
- at most 128 rules in total across all user packs;
- a file name starting with a dot is skipped;
- a symlinked directory or file is refused.

### The file format

The pack id is `user.<slug>`: 1 to 48 characters of `a-z`, `0-9` and `-`, not
starting with `-`. A user pack is always on. `default_on = false` and
`lazy = true` are errors. Unknown keys are errors too, at the top level
(`[[deny_paths]]`), in `[pack]` and in each rule, so a typo cannot silently
turn a rule off.

```toml
[pack]
id = "user.no-prod"           # required: user.<slug>
name = "Never prod"           # shown by `saiife packs`
description = "Production deploys are done by CI, not by an agent."
version = 1                   # optional, default 1
triggers = ["deploy-prod", "terraform"]   # see below
# windows_triggers = ["deploy-prod.exe"]  # extra triggers on Windows
# substitution_failsafe = true            # default true

# A command rule. `id` is required on every [[deny]]: 1 to 64 of a-z, 0-9
# and -, not starting with -, and not used twice in the pack (an error).
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
that contains one of them, so a pack with a `[[deny]]` or an `[[allow]]` and
no `triggers` is an error. `windows_triggers` count only on Windows. A pack of
path rules only needs no triggers.

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

`saiife test`, `saiife explain` and `saiife packs` read your personal packs
(the developer-mode directory). For the locked packs, use the policy
commands on the locked config:

`saiife policy check <config>` compiles every user pack beside a locked
policy, for the host and for the box profile, and prints each error. Its
`ok:` line ends with `, N user packs)` when there are any.
`saiife policy test <config>` judges each `[[example]]` with a `command =`
with those user packs too, so an example can expect `deny` or `ask` from a
`user.*` rule.

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
  `config.toml`. Run `saiife policy reload` after adding the rule, or the
  daemon refuses the request.
- **Developer mode:** there are no approvals, so it is a plain deny, and the
  reason ends with `(needs approval; approvals need locked mode)`.

## Import

`saiife rules import [FILE...]` reads the never-lines of a rules file
(`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, or any file you name) and turns the
ones saiife can enforce into a user pack. With no file named it looks for
`CLAUDE.md`, `AGENTS.md` and `GEMINI.md` in the project root. It never reads
`~/.claude/CLAUDE.md` unless you name it. `--name <slug>` names the pack
`user.<slug>` and takes one file; by default the id is
`user.<file name>-<8 hex of the path hash>`, one pack per file. When it looks
for the files itself, a file that is a symlink (`CLAUDE.md -> AGENTS.md`) or
one already imported is skipped with a one-line note and the others go on; a
file you name is refused in both cases.

A line is a candidate when it says `never`, `don't`, `do not`, `must not` and
the like, or starts with `no`. Code fences and HTML comments are skipped.
Commands in backticks (and short lists after a colon) become command rules;
paths starting with `/`, `~/` or `$VAR/` become path rules. A path becomes two
rules, the path and `path/**` (`/` becomes only `/**`). The access (`read`, `write` or `any`) comes from
the words of the line. A line with a control, bidi or format character is never
turned into a rule.

Every proposal is compiled as a one-rule pack and must pass its own examples:
it blocks what it should and allows a near miss. One that fails is listed as
unverified and never offered. The table shows each proposal with what it
blocks and what it allows, then one question per rule:

| Answer | Meaning |
| --- | --- |
| `e` | enforce |
| `a` | ask: a request to approve; offered for command rules on a locked target only |
| `s` or empty | skip (the line is kept in the pack as not enforced) |
| `x` | edit: give another target for the line |

After `e` or `a` you choose `everywhere or host only? [E/h]`; the default is
everywhere. A hint such as `(often host only)` is only a hint. A rule that
would block an everyday command or path (`ls`, `git status`, a write under
`$PROJECT/src`) is shown as `BROAD` and needs the word `yes` typed after `e`
or `a`. A one-word command rule can also get a carve-out in its own pack that
lets `<command> --help` and `<command> --version` through (never `-h`, which
is an action for some commands); it lifts only that pack's own deny, never a
built-in. The table shows its exact pattern as optional, and after the rule is
confirmed a separate question asks `also allow <command> --help and
--version? [y/N]`. The default is no: only `y` writes the carve-out. Answers from a pipe can only add restrictions or make a rule host
only. If the input ends before the last question, nothing is written and the
exit code is 1. When several files are imported and one stops after an
earlier file's pack was written, the error names the packs already written
(`earlier packs written: <ids>; this and later files unchanged`). Nothing is
written unless every user pack still loads, for the
host and for the box profile.

The pack records the source file (`source.file` is an absolute path), its
SHA-256 and, for each rule, the line it came from; the reason shown when the
rule blocks is that line quoted. A source already imported is refused with
`already imported as <id>; use saiife rules sync`. In locked mode the pack is
written root-owned; run `saiife policy reload` after adding an `ask` rule.

### The LLM pass

`saiife rules import --llm` is opt-in. After the deterministic pass, only the
candidate lines it could not use are sent (never the whole file) to
`claude -p <instructions> --tools ""`, your own Claude Code login, and the terminal says
`sending N lines of <file> to claude -p (your Claude Code login)` first. The
answer must fit a strict schema with two kinds, `command` and `path`; the LLM
never writes a regex and cannot add an allow. Its rules go through the same
builder and the same examples as the others. A missing `claude`, a timeout, a
huge or malformed answer is one warning, and the import goes on without it.

## Sync

`saiife rules sync` (all imported packs, or those named with `--pack <ID>`)
follows the source files:

- a line that moved keeps its rule; the stored line number is updated
  silently, since that loosens nothing;
- a line that is gone asks `line N is gone: "<text>" (k rules). keep? [K/r]`.
  The default is keep; `r` removes every rule from that line, carve-outs
  included. Gone `not enforced` entries are dropped;
- a new candidate line goes through the same proposals and questions as an
  import, and is never enforced unasked;
- the stored hash is updated only when the whole run finished. A missing
  source file is a warning (`source gone; rules kept`) and changes nothing;
- sync never prunes triggers (the pack's `triggers` list only grows);
- a pack left with no rules is deleted. If the input ends early, nothing is
  written for that pack.

`saiife status` prints `rules: <file> changed since it was imported (<id>);
run saiife rules sync` for a changed source and `rules: <file> is gone; its
rules stay in force (<id>)` for a missing one. It is a note: the exit code
does not change.

## Seeing what is in force

`saiife rules` (or `saiife rules list`) lists each user pack with its source
file, its rules and what is not enforced. For each rule it says where it
applies (`where=host` or `where=everywhere`), what the host does (`enforced`,
`ask`, or `ask (denied: approvals need locked mode)` in developer mode) and
what a box does (the three statuses under Boxes), the source `file:line`, and
`BROAD: blocks everyday <example>` when the rule denies an everyday command or
path. A pack whose source file changed shows `[source changed: run saiife
rules sync]`, or `[source gone]`. `--json` prints the same as data.

## What is not enforced

Import enforces only what a rule can express: a command prefix or a path. Most
of a typical rules file is something else.

- Judgement lines ("never guess", "never leave a task half done") get no rule.
  They are kept in the pack as `not enforced` entries with their line, and
  `saiife rules` lists them. In a real hard-rules file about half the
  never-lines are enforceable now; the rest are judgement or need rule types
  that do not exist yet (a tool name, a working directory, a file's content).
- A line saiife could not turn into a rule that passes its own examples is
  `unverified`; a rule you skipped is `skipped`. Both stay listed.
- A command rule is a prefix: `never use git push --force` blocks
  `git push --force origin` and allows `git push --force-with-lease`, but it
  also allows `git push origin --force`. Word order is not understood.
- A line containing a control, bidi or format character is not enforced: it is
  listed with the character replaced, never turned into a rule.
- A rule you answered `a` (ask) only asks in locked mode with approvers; in
  developer mode it is a plain deny.
- Obfuscation and interpreters (python -c) can still slip past a command rule.
- A rule marked "advisory in boxes" is not enforced in a box (see Boxes).
- Answers piped to `import` can only add restrictions; they cannot loosen
  anything or skip the `yes` for a broad rule.

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
