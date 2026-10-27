# Auditors and who can read the audit

In locked mode the audit is written by the daemon to `/var/log/saiife/audit`
(`YYYY-MM.jsonl`, owned by `saiife:saiife-audit`, mode 0640 in a 2750
directory). The agent cannot read or write it.

## Two kinds of readers

| Reader | How | Sees |
|---|---|---|
| **Auditor**: root, or a member of the group `saiife-audit` | reads the files directly | every record of every user |
| **Everyone else** | `saiife audit` asks the daemon (`audit.query`) | only records with their own uid |

Add an auditor with `usermod -aG saiife-audit <name>` (as root). Membership
is checked on the current groups at each request, so a removed auditor loses
access at once. The user needs a new login for their own shell to show the
group, but the daemon checks it directly.

### What other users get

`audit.query` returns only records whose `uid` is the asking user's, across
the `guard`, `connector` and `approval` kinds. Records of other users, and
kinds that carry no uid (daemon, policy, checkpoint, forward, ...), are not
returned, whatever the filters say. Filters (`--project`, `--service`,
`--kind`, `--agent`, `--since`, blocked only) apply after the uid scope, so
a filter can narrow the answer but never widen it. Masked inputs of other
users stay private.

The request can ask for `all: true`; that is refused unless the caller is an
auditor or root. Answers are paged: at most 5000 records, with `more` and
an opaque `next` position to send back as `after`. The position is the
month file and line, not a seq, so paging stays exact when a chain restarts
and seqs repeat. (`after_seq` and `next_seq` still work, but only on a log
with a single chain.)

## The commands

```sh
saiife audit                         # table of recent records
saiife audit --kind connector        # connector, approval or guard
saiife audit --service shopify
saiife audit --report report.html    # the same data as one HTML file
saiife audit verify                  # chain check of the local log
saiife audit verify --external <file|dir>   # against a forwarded copy
```

- As an auditor or root the CLI reads the files. As anyone else it uses the
  daemon. The tables and the report look the same; a non-auditor's covers
  their own records only.
- `saiife audit verify` is for auditors and root in locked mode. Anyone else
  gets exit 2 and `audit files need the saiife-audit group; ask an auditor`.
- The report labels guard records "reported by the agent's hook" and
  connector records "seen by saiife". Guard records are claims by a process
  running as the agent; the daemon's own records are authoritative. See
  [threats](threats.md#how-much-a-record-proves).
- `saiife audit` also shows the user's old log from before locked mode (the
  v1 log in their home folder) under the label `v1, before locked mode, not
  tamper-evident`. It is not part of the chain.
- Developer mode is unchanged: it reads the user's own log.

## Verify exit codes

| Exit | Meaning |
|---|---|
| 0 | intact (with `--external`: and every checkpoint of the copy is in the local log) |
| 1 | a break was found: local, a checkpoint of the copy missing locally, a cut-off tail, or a damaged copy |
| 2 | a log could not be read, or you may not read it |

See [forwarding](forwarding.md) for what `--external` proves.
