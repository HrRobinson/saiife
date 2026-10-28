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

## Capabilities and policy

Capabilities are `<object>:<verb>[:<qualifier>]`. Policy order is deny, then
ask, then allow; nothing matching means deny. In `allow`, a single `*` does
not cross `/` and case is compared exactly; use a trailing `**` for "every
key under". Both policies below go in `/etc/saiife/policy.d/s3.toml`.

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
