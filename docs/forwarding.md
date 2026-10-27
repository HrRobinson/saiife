# Audit forwarding

In locked mode the daemon writes a hash-chained, signed audit. The agent
cannot change it. Root can: root can stop the daemon, rewrite the files,
recompute the chain and sign new checkpoints with the local key. The only
defense against that is a copy somewhere root of this machine does not
control. Forwarding sends every record to such a copy, and `saiife audit
verify --external` compares the two.

Forwarding is off by default and is configured in
`/etc/saiife/config.toml` (not in a drop-in, and never in a project).

## Targets

One section per target, `[audit.forward.<name>]`. The name is 1 to 32 of
`a-z`, `0-9`, `_` and `-`. Every target gets every record, in order.

| `type` | Where it goes |
|---|---|
| `syslog` | RFC 5424 to the local `/dev/log`, or to a remote host over TCP with TLS (RFC 5425) |
| `file` | append JSONL to a directory, one file per host and month |
| `https` | POST batches of JSON to a URL; Splunk HEC compatible |

### Syslog

```toml
[audit.forward.local]
type = "syslog"
address = "unix:/dev/log"

[audit.forward.siem]
type = "syslog"
address = "tls://logs.acme.example:6514"
format = "rfc5424-json"      # or "rfc5424" (the default)
facility = "local0"          # local0..local7, user or daemon; default local0
ca = "/etc/saiife/ca/siem.pem"   # optional extra CA for tls://
```

- Facility is `local0` unless you set `facility`. Severity is `info`, and
  `warning` for records whose decision is `deny` or an error. The APP-NAME is
  `saiife` and the MSGID is the record kind (`guard`, `connector`, ...).
  The plain `rfc5424` format adds a structured-data element
  `[saiife@32473 seq="..."]`; `rfc5424-json` has none (`-`).
- `rfc5424-json` puts the exact JSONL line in the MSG part, unchanged. The
  plain `rfc5424` format is for log tools that want a readable line. For
  `saiife audit verify --external` use `rfc5424-json` (or `file` or
  `https`): the copy must hold the exact lines.
- The TIMESTAMP is the record's own `ts`.
- `unix:/dev/log`: one datagram per record. A message over 8 KiB is
  truncated at a character boundary and ends with `…[truncated]` (a
  truncated line cannot be verified). If `/dev/log` is a stream socket,
  every message goes over it with octet-counting framing instead, uncut.
  Note that syslog-ng's `unix-stream()` source expects newline framing by
  default; point a `unix:` target at a datagram socket (`unix-dgram()`), or
  use a framing-aware source.
- `tls://host:port`: TCP and TLS with octet-counting framing (RFC 6587 and
  5425), no ALPN, one connection per batch, 30 s per batch. The certificate
  must be valid for `host`. Trust comes from the system roots plus `ca` if
  it is set, else plus the files in `/etc/saiife/ca`. The trust store is
  read at the first send: a rotated `ca` file (or new files in
  `/etc/saiife/ca`) is picked up after the target's config changes or the
  daemon restarts. Syslog has no
  acknowledgement: a batch counts as delivered once it was written and the
  TLS session closed cleanly.

### File

```toml
[audit.forward.share]
type = "file"
path = "/mnt/audit-share"
```

Records are appended to `<path>/<host id>-YYYY-MM.jsonl`, where the month
is the record's own, as in the local month files. The directory must
exist; saiife does not create it (a share that is not mounted is a failing
target, not a directory on the local disk).

The directory must not be writable by group or others unless it has the
sticky bit, and must not itself be a symlink. Its owner is not checked: a
directory owned by another user (a share's service account, say) is used
as long as its mode passes, so choose that owner with care. A month file is
written only if it is a regular file with one link, owned by the daemon's
user; anything else (a symlink, a hard link, a file someone else created)
makes the target failing with a message that names the file. A month file
that keeps appearing and vanishing while it is opened is given up on after
5 tries and retried later. A write that hangs (an NFS server that went
away) is given up on after 60 s and retried; no second write starts while
the first is still stuck. Each file is flushed to disk after each batch.
This suits an NFS or SMB share, or a directory a log agent (Fluent Bit,
Vector) reads. Put it on a host where this machine's root cannot rewrite
the files.

### HTTPS

```toml
[audit.forward.hec]
type = "https"
url = "https://splunk.acme.example:8088/services/collector/event"
auth_secret = "splunk-hec"     # a vault secret holding the Authorization value
format = "splunk-hec"          # or "json" (the default)
ca = "/etc/saiife/ca/splunk.pem"
```

- A POST carries at most 500 records or 1 MiB of body, whichever comes
  first (one record over 1 MiB is sent alone). If the target refuses such a
  record, the `failing` reason names its `seq` and size: raise the SIEM's
  request body limit (Splunk HEC: `max_content_length`), or the target stays
  failing on that record.
- A batch can take several POSTs (Splunk HEC escaping makes a body larger
  than its lines). If a later POST fails, the whole batch is sent again,
  including the parts already accepted: delivery is at least once. Each
  POST has its own 30 s timeout, and the worker allows the batch 60 s per
  POST it takes, so a batch of several POSTs is never cut short while each
  POST is still within its own timeout.
- `auth_secret` names a secret in the vault, read at each send. Its value is
  sent as the `Authorization` header. It never appears in a log or an audit
  record. A locked vault or a missing secret is a failed send, retried.
- `format = "json"` sends a JSON array whose elements are the exact JSONL
  lines, embedded as JSON values byte for byte. A line that is not JSON
  (a foreign line in a month file; a chain that verifies has none) would
  break the array, so it is sent as a JSON string holding the line. `splunk-hec` sends one
  object per record, newline-separated: `{"event": <the line as a JSON
  string>, "sourcetype": "saiife"}`, so Splunk keeps the exact bytes.
- With a `token` secret the header is `Bearer <token>`; with a `header`
  secret the value is sent as it is. A `basic` secret is refused (the target
  stays failing until the secret is replaced).
- A 2xx answer means accepted. 429, 5xx and network errors are retried. Any
  other 4xx counts as failing and is retried with backoff too; nothing is
  ever dropped because of a 4xx. The timeout is 30 s and redirects are not
  followed (a 3xx is retried like a 4xx).
- Trust: the system roots plus `ca` if it is set, else plus the files in
  `/etc/saiife/ca`.
- The URL must be `https://`.

## What is sent

The payload is the exact JSONL line of the record, byte for byte, so that the
copy can be verified as it is. All record kinds are sent, including
`checkpoint` records: a checkpoint in the copy is what proves later that
history was not rewritten.

## Delivery, cursor and outages

- **At least once.** Each target has a worker that reads the audit month
  files after its cursor, so a restart resumes where it left off. A crash
  between a confirmed send and saving the cursor can send a few lines twice.
  `verify --external` skips resent lines and says how many; a SIEM should
  deduplicate on `seq`.
- **Cursor.** `state/forward-<name>.cursor` in the daemon's state directory
  (`/var/lib/saiife`) holds `<seq> <sha256>`: the `seq` of the last line the
  target confirmed and the SHA-256 of that line's exact bytes. The hash
  tells it apart from a line with the same `seq` in a later chain. It
  advances only after the target confirms. A cursor file that cannot be
  read as such starts the target at the oldest line, with a warning.
- **Chain restarts.** When the chain was restarted (a new genesis, so seqs
  start again) and the cursor's line is no longer found, the worker goes on
  at the oldest line of the log. The target then gets duplicates, but no
  chain between the cursor's and the newest is skipped.
- **Config changes.** A target whose config changes (a new address, say)
  keeps its cursor and goes on where it was. To send the whole log to a new
  destination, give the target a new name: a new name has no cursor and
  starts at the oldest line.
- **Never in the way.** Forwarding does not slow the audit writer or the
  hooks. A target that is down for hours builds a backlog on disk; nothing
  waits for it.
- **Retries.** Exponential backoff from 1 s to 60 s, forever. A send that
  neither succeeds nor fails within 60 s (a target that hangs) counts as a
  failure too; an HTTPS batch gets 60 s for each POST it takes.
- **Backlog limit.** The backlog is the audit itself, so nothing is lost
  until retention (`[audit] retention_months`) deletes a month file the
  cursor still needs. Then one `backlog_dropped` record names the range of
  `seq` that was never delivered.

### What the audit records

Changes in a target's state are records of kind `forward`, with the target
name and an `event`:

| event | when |
|---|---|
| `connected` | the first successful delivery after the target's worker started (daemon start, or a reload that added or changed the target) |
| `failing` | delivery has been failing for more than 30 s |
| `recovered` | the next delivery succeeded after `failing` |
| `backlog_dropped` | retention deleted records the target had not received; `from_seq` and `to_seq` name them |

Individual batches are not recorded (that would feed back into the log). A
`forward_failing` notification (see [notifications](notifications.md)) is
sent once per outage when it lasts more than 5 minutes.

`saiife audit --report` lists forwarding outages: from `failing` to the
next `recovered`, or to a later `connected`, noted "recovered after a daemon
restart or reload" (a restarted worker records `connected`, not
`recovered`). An outage still open at the end of the report is `ongoing`.
Dropped backlogs are listed with their `seq` range. A report built from the
daemon's answer (a user who is not an auditor) cannot see `daemon` or
`forward` records, so its restart and outage sections say "Not shown:
auditors only."

`saiife doctor` shows the `forwarding` check: the configured targets by name
and type. Their state is not asked there; it is in the log. A quiet SIEM is
not the same as a quiet machine, which is why state changes are in the log.

## Verifying the copy

```sh
saiife audit verify                       # the local log
saiife audit verify --external <file|dir> # the local log against a copy
```

`--external` takes one file or a directory of month files (a `file` target's
directory, or an export from your SIEM, as JSONL lines). The copy must hold
the exact bytes of each line. From a SIEM, export the forwarded lines raw:
for `format = "json"` the array elements as they arrived, for
`splunk-hec` the decoded `event` strings, for `rfc5424-json` the MSG part,
one per line. A copy that the SIEM re-serialized (keys reordered, spaces or
escapes changed, numbers reformatted) cannot verify: every line of it looks
edited.

It checks:

1. The local log itself, as `verify` does.
2. The copy, as a chain of its own. Problems in the copy are printed as
   `external copy damaged` and are never blamed on the local log.
3. That the local log holds every checkpoint the copy has: the same
   `head_seq`, `head` and signature. A missing one is reported as `local log
   REWRITTEN OR CUT`.
4. That the copy does not reach beyond the local log: if its highest `seq` is
   higher, the output says `local log CUT OFF` (the newest records were
   removed locally after they were forwarded).
5. That the last line of each intact stretch of the copy is in the local
   log byte for byte at its `seq`. A difference after a checkpoint the
   local log holds is `local log REWRITTEN after seq N`; one that no
   checkpoint vouches for says that one of the two was changed.

Lines the target got twice (at least once delivery) are skipped and
counted: `N resent lines skipped`.

Exit codes: 0 when the local log is intact and holds everything in the copy,
1 on any break (local, a missing checkpoint, a rewritten line, a cut-off
tail, or a damaged copy), 2 when either side cannot be read. The output names counts, files and
sequence numbers, never record content.

A copy that starts in the middle of the chain is fine: its checkpoints are
vouched for by the local log. Files named for another host id get a note
(`the copy's files are named for host …, not this machine`); the check
still runs.

## What this does not do

- It does not stop root from rewriting the local log. It makes that visible,
  as long as the copy lives where root of this machine cannot change it and
  was forwarded before the rewrite.
- Records not yet delivered at the time of the rewrite are not in the copy.
  A target that is failing is shown by its `forward` records and the
  notification.
- Developer mode has no forwarding and no signing key.
