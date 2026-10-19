# Cloud: aws (cloud.aws)

This pack stops AWS command-line operations that cannot be undone: deleting
stacks, tables, databases and instances, emptying S3 buckets, changing IAM
permissions in ways that grant or lock out access, and changing the AWS
organization. Commands that only look (`describe`, `list`, `get`) are never
blocked.

## On by default

No. Turn it on for a project in your own terminal:

- run `saiife init --pack cloud.aws`, or
- add the id to the `packs` list in `.saiife/config.toml`, for example
  `packs = ["cloud.aws"]`.

To turn it off, remove the id from that list. An agent cannot change this
file (the `core.self` pack blocks it).

## Blocked

- `cloudformation delete-stack`. It deletes a stack and, depending on its
  settings, the resources in it.
- `s3 rb --force` (removes a bucket and every object in it) and
  `s3 rm --recursive` (deletes every object under a prefix).
- `ec2 terminate-instances`. Terminated instances are gone; use
  `stop-instances` instead.
- Deleting an RDS database without a final snapshot. It cannot be recovered.
- `dynamodb delete-table`. It deletes the table and all its data.
- IAM changes: deleting a role or user, detaching a policy, writing an inline
  policy (`put-role-policy`, `put-user-policy`, `put-group-policy`,
  `create-policy-version`), and attaching `AdministratorAccess`. These can
  give an identity full access, or lock people out.
- Any change to AWS Organizations. It affects every account in the
  organization.
- Any other operation whose name starts with `delete`, or contains
  `terminate` or `force`. Check what it affects before you run it.

These rules also apply with global options before the service
(`aws --profile prod --region eu-west-1 ...`) and through `sudo`.

## Allowed on purpose

- Read commands: `describe-*`, `list-*`, `get-*`, `s3 ls`.
- Deleting an RDS database with `--final-db-snapshot-identifier`. The
  snapshot keeps it recoverable.
- Routine deletes that destroy no data or only one recoverable item: SQS
  `delete-message` and `delete-message-batch`, `delete-tags`, and
  `s3api delete-object` of a single object.
- Deleting a single S3 object with `s3 rm` (no `--recursive`).
- A resource that is only named like an operation, for example a bucket
  called `delete-me`.

## Not covered

- Only the `aws` command is judged. Changes made through the AWS console,
  CloudFormation templates, Terraform (see `iac.terraform`) or SDK scripts
  are not seen.
- Creating resources, changing settings and other non-delete changes are
  allowed, even when they cost money or open access (for example a security
  group rule).
- Reading AWS secrets (Secrets Manager, SSM, access keys) is covered by
  `core.secrets`, not by this pack.

## Examples

```saiife-examples
deny aws cloudformation delete-stack --stack-name prod
deny aws s3 rb s3://my-bucket --force
deny aws s3 rm s3://my-bucket --recursive
deny aws ec2 terminate-instances --instance-ids i-0abc
deny aws rds delete-db-instance --db-instance-identifier prod --skip-final-snapshot
deny aws --profile prod dynamodb delete-table --table-name users
deny aws iam attach-role-policy --role-name r --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
deny aws organizations detach-policy --policy-id p-1 --target-id ou-1
deny aws lambda delete-function --function-name f
allow aws ec2 describe-instances
allow aws s3 ls s3://delete-me
allow aws rds delete-db-instance --db-instance-identifier prod --final-db-snapshot-identifier snap-1
allow aws s3 rm s3://my-bucket/one-object.txt
allow aws sqs delete-message --queue-url https://q --receipt-handle h
```
