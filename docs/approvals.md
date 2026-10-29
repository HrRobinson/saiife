# Approvals

Locked mode (Linux). An `ask` rule does not allow or deny a call. It parks the
call until a person you named decides. Two kinds of call can wait:

- a connector request, when its capability is in a service's `ask` list;
- a command, when the deny rule that blocked it is in `[guard] ask`.

Both go through the same store and the same records.

## The flow

1. The agent makes the call. The daemon seals the exact request with the vault
   key, stores a masked copy for display, writes an `approval` record with
   `action = "created"` and, if a notification target is set, sends
   `approval_created` (see [notifications](notifications.md)).
2. The caller is told the request is pending. It does not wait for a person
   unless it asks to (`--wait`).
3. An approver runs `saiife approvals` to list, `saiife approvals show <id>` to
   read, then `saiife approve <id>` or `saiife reject <id>`.
4. On approval a connector request is re-checked against the policy and the
   limits as they are now, then sent exactly as stored. A command request
   becomes a one-use grant.
5. Every step is a record of kind `approval`, linked by the request `id`
   (see [the records](#the-records)).

A connector request whose body the masker would change (a vault value, or a
text a masking pattern matches) is never stored for approval: the approver
could not see what would be sent. It is a plain deny with the rule
`masked_content`: "cannot be approved: the request contains masked content".

A binary request body (one that is not UTF-8 text, such as an image uploaded
with a `raw` body) cannot be shown either. It is a plain deny with the rule
`body_not_displayable`: "cannot be approved: the request body is binary and
cannot be shown for approval". Put such uploads under `allow`, with limits.

A request that nobody decides expires after `[approval] timeout` (default
`30m`). Results are kept 24 hours. A request can never be sent after it
expired, was rejected or was sent.

## The records

Each `approval` record has `action`, `id` (also as `approval`), `by_uid` and
`note` when a person decided, and `rule`/`reason` when something was refused
or failed:

| action | when |
|---|---|
| `created` | a request was made |
| `approved` | an approver approved it |
| `rejected` | an approver rejected it, or the requester withdrew it (note `cancelled by requester`) |
| `refused` | a decision was refused (`not_approver`, `same_user`, `reauth_failed`, `reauth_unavailable`, `reauth_error`, `reauth_busy`, `reauth_cooldown`, `truncated_not_acknowledged`), or a command request was not made (`not_ask`, `ask_rule_mismatch`, `raw_mismatch`, `project_mismatch`); nothing changed |
| `expired` | nobody decided in time |
| `sent` | a connector request was sent; for a command, the one-use grant was kept (the command may run once) |
| `grant_used` | the approved command ran: its grant was used up |
| `send_failed` | an approved request was not sent; `rule` says why: `policy_changed`, a `limit`, `lockdown`, `body_changed` (the body about to be sent no longer hashes to the one shown), `env_changed` (the request was asked under an environment it would no longer be sent under: a locked scope rebound to another one, or a developer-mode environment no longer defined; a request with no environment is not checked), `vault_unavailable`, `grants_unavailable`, or `interrupted` (the daemon stopped between the approval and the send; it is never sent by itself, and a command's grant is revoked) |

A result that could not be kept (it could not be sealed or written) is
`result_unavailable`: `saiife api result` says so, and `GET
/v1/requests/{id}` answers 410 with `"error": "result_unavailable"`.

A caller may have at most 20 pending requests. The 21st is denied at once with
`approvals_full` (a command says: "Too many pending approval requests (20); ask
an approver to decide the open ones.").

If anything on the way fails (the store cannot be read, the vault is not
available to seal, the record cannot be written), the call is denied and
nothing is left pending. Approval fails closed.

## Who may approve

```toml
[approval]
approvers = ["boss", "group:ops"]
same_user = "deny"      # or "reauth"
timeout = "30m"
grant_ttl = "15m"
```

- Only a user listed in `approvers` (a name, or `group:<name>`) can decide.
  Being root or in an `[admin]` group is not enough.
- The requester sees its own requests (`saiife approvals`, `saiife api
  result`). Approvers see every request. Anyone else sees nothing, as if the id
  did not exist.
- `same_user = "deny"` (the default): an approver can never decide a request
  made under their own uid. The refusal is recorded as `refused` with rule
  `same_user`. Use a second account for approving.
- `same_user = "reauth"`: an approver may decide their own request after
  re-authenticating through polkit (below). Use this on a machine with one
  person and no second account.
- The requester may always withdraw its own request with `saiife reject`: no
  approver list, no re-authentication. It is recorded as `rejected` with the
  note `cancelled by requester`.

## Re-authentication and the fallback

With `same_user = "reauth"` the daemon runs `pkcheck --action-id
com.saiife.approve` for the approving CLI process, with `--detail request
"#<id> <service> <operation>"` (or `#<id> <pack>/<rule>` for a command, or
`lockdown off`), which the prompt shows. The polkit action is installed by
`saiife system install` in
`/usr/share/polkit-1/actions/com.saiife.approve.policy`, with `auth_self` for
all three kinds of session (never `auth_self_keep`, so every approval asks
again). It names the daemon user (`unix-user:saiife`) as the action's owner:
polkit lets only root or an action owner check another user's process.
`saiife doctor` checks the file byte for byte. The wait is 120 seconds.
Anything but "authorized" refuses the decision with `reauth_failed`; an error
or an unreadable answer is `reauth_error`. The first line of pkcheck's error
output is kept in the refusal's reason.

After a prompt that was denied, dismissed, timed out or failed, the approver's
uid cools down: the next decision that needs a prompt is refused with
`reauth_cooldown` for 30 seconds, then 60, doubling up to 10 minutes; a
success resets it. So an agent cannot flood its user with password prompts.
Before it starts `pkttyagent`, `saiife approve` prints what it approves (id,
type, service and operation or command, amount).

The approving CLI starts `pkttyagent --fallback` for you when it runs in a
terminal-only session (`SSH_TTY` is set, or neither `DISPLAY` nor
`WAYLAND_DISPLAY` is). That is the fallback: a text password prompt where no
desktop agent can show a dialog. The CLI stops its own helper afterwards
(SIGTERM, then SIGKILL after a second). When `/usr/bin/pkttyagent` is missing
it says so.

When polkit or the action file is missing, `same_user = "reauth"` cannot work.
Decisions are refused with `reauth_unavailable`, and `saiife doctor` warns:
`re-authentication unavailable: approvals need a second account`.

Only one re-authentication runs per approver at a time; a second decision
while one is waiting is refused with `reauth_busy`.

The action file decides how strong this check is, and a polkit rule could
answer yes for the action without a password. Both are root-owned, so an agent
user cannot edit them, and `core.lock` also denies write attempts through tool
calls to `/etc/polkit-1`, `/run/polkit-1`, `/usr/local/share/polkit-1` and
`/usr/share/polkit-1`. Reading them is allowed: the files are public. `saiife
doctor` warns when a rule in one of their `rules.d` folders mentions
`com.saiife.approve`.

## Command grants

When a command is denied by a rule you listed in `[guard] ask`, the hook creates
a request with the command and exits 2 with:

```
Needs approval: request #<id>. Run the same command again after it is approved.
```

When an approver approves, saiife keeps a grant. A grant is narrow:

- **Exact command only.** The key is a SHA-256 over the user, agent, project,
  tool and the command text, each length-prefixed. A different command, agent,
  user or project does not match.
- **Never for masked, overlong or compound commands.** If the command
  contains anything the audit log would mask, is too long to show whole, or
  another rule denies it as well (`a && git push --force`), there is no request.
  It is a plain deny: "cannot be approved: the command contains masked or
  overlong content". What an approver sees is always exactly what would run.
- **Scope = the project root.** The grant is for the project the command was
  run in (the directory with `.saiife/config.toml`, or the working directory),
  and the working directory must lie inside it.
- **One use.** The first matching run consumes it; the next asks again.
- **15 minutes.** A grant that is not used within `[approval] grant_ttl` lapses.

Asking again for a command that already has a pending request returns the same
request, with no second record or notification.

## Rule ids

Records keep `rule` as the regular expression that matched. They also carry
`rule_id`, a stable name such as `core.git/force-push`, which is what `[guard]
ask` lists. In v2.0 only the `core.git` and `db.postgres` packs and the
Kubernetes delete-namespace rule have ids, so only those can be put in `ask`. A
project config cannot define packs or ids.

The design spec's example guard record (section 8.5) shows `"rule":"force-push"`.
Real records carry `rule` as the matched expression and `rule_id` as the
stable name (`core.git/force-push`); use `rule_id` in `ask`, scripts and
SIEM queries.

## Connector requests

`saiife api <service> <operation> ...` exits with these codes:

| Code | Meaning |
|------|---------|
| 0 | done |
| 1 | the upstream answered 400 or more, or failed |
| 2 | denied (including a rejected or expired request) |
| 3 | pending approval: the id is printed, and how to get the result |
| 4 | a limit was reached |
| 5 | saiife is unavailable |

- `saiife api ... --wait 10m` polls every 2 seconds for the decision and the
  result, up to the given time (at most `1h`), and exits as a direct call
  would. Without it, exit 3 comes back at once.
- `saiife api result <id>` fetches the result later (for the requester only,
  for 24 hours).
- Over HTTP the gateway answers `202 {"pending": <id>}`; poll `GET
  /v1/requests/{id}` for the state and the result. A `wait` field in the HTTP
  call is ignored: the answer is always at once.

The amount of money in the call, if the operation moves any, is shown to the
approver and counted against the amount limits when the request is sent, not
when it is made.

## Approver commands

```
saiife approvals [--all | --pending] [--json]
saiife approvals show <id> [--full] [--json]
saiife approve <id> [--note TEXT] [--accept-truncated]
saiife reject  <id> [--note TEXT]
```

- `approvals` lists pending requests by default; `--all` adds the decided ones.
- `show` prints what would be sent, masked: the service, operation, the
  environment it was asked under (it is sent under that one or not at all),
  amount, headers and body (the first 2000 characters, plus the SHA-256 of
  the whole body). `--full` prints the whole masked body. `--json` always has the whole
  masked body (`--full` changes only the text output).
- `approve` of a request whose body is over 1 MiB and was shown cut is refused
  unless you pass `--accept-truncated`: you decide on a body you have not seen
  whole, and the record says so.
- A refused decision exits 2; an unreachable daemon exits 5, and so does a
  decision the daemon made but could not record (`unrecorded`): check
  `saiife approvals show`.

## Limits at send time

At creation the limits are only checked, not used: a request that could never
be sent is denied at once with its `limit`. At send time they are used for real.
If the limit is reached by then, the request ends as `send_failed` with that
`limit`, and the result says so. A policy that now says `deny` ends a request as
`send_failed` with rule `policy_changed`. While lockdown is on, nothing is sent
and nothing new can be asked.
