# AWS STS connector

The `aws-sts` connector reaches one AWS Security Token Service action,
`GetCallerIdentity`, through `saiifed`. It answers "which account and
principal do these credentials belong to" and grants nothing. The daemon
signs the request with AWS Signature Version 4; the agent never sees the
access key. The manifest is `crates/broker/connectors/aws-sts.toml`,
embedded at build time.

- Base URL `https://sts.{region}.amazonaws.com` (the regional endpoint).
  `region` is a service param set by the admin, never by the agent.
- Auth: `aws_sigv4`, service `sts`. The vault entry is an `aws` secret.
- The action and the API version are fixed query parameters
  (`Action=GetCallerIdentity&Version=2011-06-15`): a call that sets them is
  refused, so the agent cannot run another STS action. No request header is
  accepted from the agent.
- Vendor reference:
  <https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html>,
  <https://docs.aws.amazon.com/general/latest/gr/sts.html>.

## Operations

| Operation | Capability | Kind | Request | IAM action |
|---|---|---|---|---|
| `sts.get_caller_identity` | `sts:read` | read | `GET /?Action=GetCallerIdentity&Version=2011-06-15` | `sts:GetCallerIdentity` |

The answer is XML, passed through as text and masked.

```bash
saiife api sts sts.get_caller_identity
```

## The secret

The vault kind is `aws`, with `access_key_id`, `secret_access_key` and an
optional `session_token`:

```sh
saiife secret add aws-prod --kind aws --service sts
saiife connect sts --connector aws-sts --secret aws-prod --param region=us-east-1
```

## Minimum permissions in AWS

`sts:GetCallerIdentity` needs no IAM permission: any valid credential can
call it. Give the key only what its other services need.

## Not the STS mode

This connector is the sign-mode call `GetCallerIdentity`. It is not
`mode = "sts"`, which hands short-lived credentials to a command; that is a
setting of a service such as [Amazon S3](aws-s3.md#sts-mode).

## Capabilities and policy

There is no write operation. The policy goes in
`/etc/saiife/policy.d/sts.toml`.

## Suggested policy: read-only

```toml
[services.sts]
connector = "aws-sts"
secret = "aws-prod"
allow = ["sts:read"]

[services.sts.params]
region = "us-east-1"
```

## Suggested policy: every write under `ask`

The connector has no write; this is the same policy, kept so every connector
page has one.

```toml
[services.sts]
connector = "aws-sts"
secret = "aws-prod"
allow = ["sts:read"]

[services.sts.params]
region = "us-east-1"
```

## Locked mode

In locked mode (Linux) the agent user reaches STS only through `saiifed`.
The keys live in the daemon's vault (`saiife secret add aws-prod --kind aws
--service sts`) and never reach the agent's environment, files or audit
records. Every call is one `connector` audit record.
