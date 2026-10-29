# Amazon S3 connector

The `aws-s3` connector reaches the Amazon S3 REST API (list, get, head, put
and delete objects) through `saiifed`. The daemon signs each request itself
with AWS Signature Version 4; the agent never sees the access key. The
manifest is `crates/broker/connectors/aws-s3.toml`, embedded at build time.

- Base URL `https://s3.{region}.amazonaws.com`, path-style
  (`/{bucket}/{key}`). `region` is a service param set by the admin
  (`[services.<name>.params]`), never by the agent. It is one DNS label, so
  it cannot change the domain. With virtual-hosted style the agent would
  choose the host, so it is not used.
- A bucket in another region answers 301, which is refused as
  `redirect_refused`: set `params.region` to the bucket's region (one
  service per region).
- Auth: `aws_sigv4`, service `s3`. The vault entry is an `aws` secret
  (`access_key_id`, `secret_access_key`, optional `session_token`). With
  `[services.<name>.cloud] role_arn`, the daemon signs with credentials from
  `sts:AssumeRole` instead.
- Request headers the agent may send: `Content-Type` and `Range`.
  `Authorization`, `Cookie` and `Host` are always dropped. Every header
  present is signed and the policy does not see headers, so no header that
  changes what a call does is accepted: `x-amz-copy-source`, `x-amz-acl`,
  `x-amz-grant-*`, the encryption, tagging, object-lock, MFA and
  request-payer headers are all dropped.
- Vendor reference:
  <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html>,
  <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html>,
  <https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html>,
  <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html>,
  <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html>.

## Operations

| Operation | Capability | Kind | Request | IAM action |
|---|---|---|---|---|
| `s3.list_objects` | `s3:read` | read | `GET /{bucket}?list-type=2` | `s3:ListBucket` |
| `s3.get_object` | `s3:read` | read | `GET /{bucket}/{key}` | `s3:GetObject` |
| `s3.head_object` | `s3:read` | read | `HEAD /{bucket}/{key}` | `s3:GetObject` |
| `s3.put_object` | `s3:write` | write | `PUT /{bucket}/{key}` | `s3:PutObject` |
| `s3.delete_object` | `s3:delete` | delete | `DELETE /{bucket}/{key}` | `s3:DeleteObject` |

The qualifier is the S3 ARN: `arn:aws:s3:::{bucket}` for the list and
`arn:aws:s3:::{bucket}/{key}` for the object operations.

Parameters:

- `bucket`: a bucket name (lower case, 3 to 63 characters).
- `key`: an object key, which may hold `/`. Each segment is percent-encoded
  and `/` is kept. An empty key, an empty segment (`a//b`), a `.` or `..`
  segment, a backslash or a control character is refused, also when
  percent-encoded.
- `s3.list_objects`: `prefix`, `delimiter`, `max-keys` (1 to 1000),
  `continuation-token` and `start-after`.
- `s3.put_object`: the body is sent as it is (`body = "raw"`).

Answers are XML (or the object's bytes) and are passed through as text,
masked. `s3.list_objects` is paged by hand: pass the answer's
`NextContinuationToken` back as `continuation-token`.

```bash
saiife api s3 s3.list_objects bucket=acme-logs prefix=2026/10/
saiife api s3 s3.get_object bucket=acme-logs key=2026/10/report.json
saiife api s3 s3.put_object bucket=acme-logs key=out/summary.txt --body @summary.txt
```

## The secret

The vault kind is `aws`, with the fields `access_key_id`, `secret_access_key`
and an optional `session_token`. Add it with the paste flow, or let
`saiife connect` do it:

```sh
saiife secret add aws-prod --kind aws --service s3
saiife connect s3 --connector aws-s3 --param region=eu-west-1
```

`saiife connect` writes a deny-all policy file with a commented
`# mode = "sts"` block (see [STS mode](#sts-mode)). A secret can only be used
by the services in its `allowed_services` list.

## Capability and IAM action

The capability is what the saiife policy sees. The IAM action is what the
request needs in AWS, and what an STS session policy is built from. Several
operations share a capability, so the IAM column is the one to read when you
size the IAM policy.

| Capability | Operations | IAM action | Resource |
|---|---|---|---|
| `s3:read` | `s3.list_objects` | `s3:ListBucket` | `arn:aws:s3:::<bucket>` |
| `s3:read` | `s3.get_object`, `s3.head_object` | `s3:GetObject` | `arn:aws:s3:::<bucket>/<key>` |
| `s3:write` | `s3.put_object` | `s3:PutObject` | `arn:aws:s3:::<bucket>/<key>` |
| `s3:delete` | `s3.delete_object` | `s3:DeleteObject` | `arn:aws:s3:::<bucket>/<key>` |

## Minimum permissions in AWS

Give the IAM user (or the role) only what the saiife policy allows. For the
read-only policy below that is `s3:ListBucket` on the bucket and
`s3:GetObject` on its objects:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::acme-logs" },
    { "Effect": "Allow", "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::acme-logs/*" }
  ]
}
```

Add `s3:PutObject` or `s3:DeleteObject` only for the writes you put under
`ask`. For STS mode the IAM user needs only `sts:AssumeRole` on the role,
and the role carries the S3 permissions above.

## Capabilities and policy

Capabilities are `<object>:<verb>[:<qualifier>]`. Policy order is deny, then
ask, then allow; nothing matching means deny. In `allow`, a single `*` does
not cross `/` and case is compared exactly; use a trailing `**` for "every
key under". Both policies below go in `/etc/saiife/policy.d/s3.toml`.

## Sign mode and STS mode

A service has one of two modes, set by the admin in the policy
(`mode = "sign"` is the default).

| | `sign` (default) | `sts` (opt-in) |
|---|---|---|
| Who holds the credential | the daemon only | the one command you start, for at most 15 minutes |
| How the agent reaches S3 | `saiife api`, or the gateway | any tool, through `saiife run --cloud` |
| Cost | the agent needs saiife's operations | **a credential reaches agent-controlled code** |

Sign mode is the one to use. The agent never sees a credential, and the
policy decides every call. With `[services.<name>.cloud] role_arn`, the
daemon signs with `sts:AssumeRole` credentials (3600 s, no session policy)
that it keeps in memory, instead of the vault keys.

## STS mode

Many tools (terraform, the aws CLI) cannot work through a signing proxy.
For them, STS mode lets `saiife run --cloud` hand one command a credential.

> This hands a credential to agent-controlled code. It is scoped and short-lived, but an agent can copy it.

```sh
saiife run --cloud s3 -- /usr/local/bin/aws s3 ls s3://acme-logs
```

Each run is one `sts:AssumeRole` call with `DurationSeconds = 900` (the AWS
minimum and the saiife maximum) and an inline session policy built from the
service's saiife policy. The credentials go into that command's environment
only, and its output is masked.

```toml
[services.s3]
connector = "aws-s3"
secret = "aws-prod"
mode = "sts"
allow = ["s3:read:arn:aws:s3:::acme-logs", "s3:read:arn:aws:s3:::acme-logs/**"]

[services.s3.params]
region = "eu-west-1"

[services.s3.cloud]
role_arn = "arn:aws:iam::123456789012:role/saiife-s3-reader"
run_allow = ["/usr/local/bin/aws"]
```

`role_arn` and `run_allow` are required. `external_id` is optional. The
`aws` secret needs only `sts:AssumeRole` on the role. `doctor` warns once for
each service in STS mode (`cloud_sts.<service>`), and adds an info line
about `run_allow`.

### The trust boundary

Read this before you turn STS mode on.

- **Any process of your user can ask for a lease** (`cloud.lease`). The
  `run_allow` check is made by the honest `saiife` client; it does not bind
  a process that talks to the daemon directly.
- The check itself: the program must be listed in `cloud.run_allow`, resolve
  to a canonical path in a root-owned chain, and not be an interpreter or a
  shell. That holds through symlinks, and `env` counts as an interpreter.
- The command, and anything it starts, can copy the credentials. They last
  at most 900 s and stay within the session policy, but they work from
  anywhere until then.
- Each lease is a `secret` record with `event = "cloud_lease"`. It holds
  `service`, `exe`, `role_arn`, `expires`, `policy_sha256` and the STS
  session name in `sts_session` (the record's `session` is the agent
  session). It never holds a credential value. The `cloud.lease` answer
  names the STS session `session`.
- Under the personal broker a lease runs under the broker's base config,
  with no project `env`.

### The session policy

The session policy is built only from the admin config and the manifest.

- An `allow` pattern gives `Allow <IAM action>` on its qualifier. A missing
  qualifier means `*`, and a trailing `**` means `*`.
- A single `*`, `?`, `$`, `{` or `}` inside an allow qualifier makes the
  service unrepresentable, and the lease is refused: IAM's `*` crosses `/`,
  and `?` and `${...}` are IAM syntax. An `allow` rule with `when` is
  refused too.
- `ask` and `deny` patterns, and `ask` and `deny` rules, become `Deny`
  statements. A project overlay can only add these. An overlay `allow` is
  ignored.
- IAM turns some characters into `?`, so a `Deny` can match a little more
  than the saiife pattern does. It never matches less.
- The policy is at most 2048 bytes. Its SHA-256 is in the lease record.
- There is no region condition: the credential works in every region the
  role allows.
- The China partition (`aws-cn`) is not supported.

### Limits in STS mode

Only `requests_per_minute` applies, one per lease, and it is counted again
after a daemon restart. The other limits count `saiife api` calls, so they
cannot bind a credential that was already handed out. Do not set them for a
service in STS mode: `saiife policy check` warns.

### The environment of the command

`saiife run --cloud` sets `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`AWS_SESSION_TOKEN`, `AWS_REGION` and `AWS_DEFAULT_REGION`. It sets
`AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` to `/dev/null`. It
removes `AWS_PROFILE`, `AWS_DEFAULT_PROFILE`, `AWS_ROLE_ARN`,
`AWS_WEB_IDENTITY_TOKEN_FILE` and `AWS_CONTAINER_*`. It also removes
`AWS_ENDPOINT_URL`, every `AWS_ENDPOINT_URL_*` and `AWS_CA_BUNDLE`, so an
inherited environment cannot send the credentials to another endpoint. A
local endpoint override (localstack) therefore does not work under
`run --cloud`.

Before the command starts, saiife prints one line to stderr:

```
saiife: AWS credentials for s3 (STS mode) expire at 2026-10-29T12:15:00Z; this command and anything it starts can read them
```

The exit codes are those of `run --secret`: 2 refused, 5 unavailable,
otherwise the command's own code. `--cloud` cannot be combined with
`--secret`. A lease is refused with one of these rules: `lockdown`,
`no_scope`, `scope_conflict`, `sts_not_enabled`, `exe_not_allowed`,
`secret_missing`, `secret_not_allowed_for_service`, `vault_unavailable`,
`session_policy_unrepresentable`, `session_policy_too_large`,
`token_mint_failed` or `limited` (`requests_per_minute`). A failed mint
records the AWS error code only, never its message.

## Suggested policy: read-only

```toml
[services.s3]
connector = "aws-s3"
secret = "aws-prod"
allow = ["s3:read:arn:aws:s3:::acme-logs", "s3:read:arn:aws:s3:::acme-logs/**"]

[services.s3.params]
region = "eu-west-1"
```

Writes and deletes are denied (`default_deny`).

## Suggested policy: every write under `ask`

```toml
[services.s3]
connector = "aws-s3"
secret = "aws-prod"
allow = ["s3:read:arn:aws:s3:::acme-logs", "s3:read:arn:aws:s3:::acme-logs/**"]
ask   = ["s3:write", "s3:delete"]

[services.s3.params]
region = "eu-west-1"
```

## Known limits

- **Folder-marker keys.** A key that ends in `/` (the console's "folder"
  object) is refused: an empty segment is not accepted. Use the object's
  real key, or list with `prefix` and `delimiter`.
- Presigned URLs, multipart uploads, copy and tagging are not operations.
- STS mode is AWS only for now; GCP and Azure have no equivalent.

## Limits

- Per-service `limits` in the policy count requests that were sent upstream.
- Responses over `max_response_bytes` (default 5 242 880) are cut off.
- The access key, the secret key and any session token are masked in every
  answer (raw, base64, URL-encoded and hex forms).

## Locked mode

In locked mode (Linux) the agent user reaches S3 only through `saiifed`:
`saiife api s3 ...`, or `gateway.sock` at `/v1/api` and `/v1/proxy`. The
keys live in the daemon's vault (`saiife secret add aws-prod --kind aws
--service s3`) and never reach the agent's environment, files or audit
records. A project overlay can only add `deny` and `ask`; in locked mode its
`allow` is ignored. Every call is one `connector` audit record.

Give the key an IAM policy limited to what the saiife policy allows, so a
policy mistake is bounded by the key.
