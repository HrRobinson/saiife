//! Golden corpus for `cloud.aws` (opt-in — must be enabled explicitly).
//!
//! Precision is the whole point: read verbs and resource names that merely
//! contain "delete" must pass, while genuinely irreversible operations must
//! block. The RDS snapshot carve-out (a delete WITH `--final-db-snapshot-
//! identifier` is recoverable → allowed) is tested explicitly.

use saiifeguard::builtins::builtin_packs;
use saiifeguard::engine::{Decision, Engine};
use saiifeguard::profile::select_active;

fn engine() -> Engine {
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    Engine::new(select_active(packs, &["cloud.aws".to_string()]))
}

fn deny(e: &Engine, cmd: &str) -> (String, String) {
    match e.evaluate(cmd) {
        Decision::Deny { pack, reason, .. } => (pack, reason),
        other => panic!("expected DENY for {cmd:?}, got {other:?}"),
    }
}

#[test]
fn denies_destructive_aws_commands() {
    let e = engine();
    // (command, substring the reason must contain — proves the class is named)
    let cases = [
        // CloudFormation
        (
            "aws cloudformation delete-stack --stack-name prod",
            "stack",
        ),
        // S3 force-remove / recursive delete
        ("aws s3 rb s3://my-bucket --force", "bucket"),
        ("aws s3 rm s3://my-bucket/data --recursive", "object"),
        (
            "aws s3 rm s3://my-bucket --recursive --exclude '*.keep'",
            "object",
        ),
        // EC2 terminate
        (
            "aws ec2 terminate-instances --instance-ids i-0abc",
            "terminate",
        ),
        // RDS delete without a final snapshot
        (
            "aws rds delete-db-instance --db-instance-identifier prod",
            "snapshot",
        ),
        (
            "aws rds delete-db-instance --db-instance-identifier prod --skip-final-snapshot",
            "snapshot",
        ),
        (
            "aws rds delete-db-cluster --db-cluster-identifier prod",
            "snapshot",
        ),
        // DynamoDB
        ("aws dynamodb delete-table --table-name users", "table"),
        // a destructive command still blocks even when a preceding global's
        // value looks destructive (the value must not consume the service slot)
        (
            "aws --profile delete-me dynamodb delete-table --table-name t",
            "table",
        ),
        // IAM self-priv-esc shapes
        ("aws iam delete-role --role-name saiife-agent", "IAM"),
        ("aws iam delete-user --user-name svc", "IAM"),
        (
            "aws iam detach-role-policy --role-name r --policy-arn arn:aws:iam::aws:policy/Foo",
            "IAM",
        ),
        (
            "aws iam attach-role-policy --role-name r --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
            "AdministratorAccess",
        ),
        (
            "aws iam attach-user-policy --user-name u --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
            "AdministratorAccess",
        ),
        // Organizations
        ("aws organizations delete-organization", "Organizations"),
        ("aws organizations leave-organization", "Organizations"),
        (
            "aws organizations detach-policy --policy-id p-1 --target-id ou-1",
            "Organizations",
        ),
        // Catch-all — destructive long tail not covered by a specific rule
        (
            "aws lambda delete-function --function-name f",
            "destructive",
        ),
        ("aws ec2 delete-vpc --vpc-id vpc-1", "destructive"),
        ("aws ecs delete-service --service svc", "destructive"),
        // Bulk S3 multi-object delete is NOT one of the routine carve-outs
        // (only single `delete-object` is) — the catch-all must still block it.
        (
            "aws s3api delete-objects --bucket b --delete file://d.json",
            "destructive",
        ),
        // C1 — a global option BEFORE the service must not shift the service
        // out of the anchor. Separate-token AND `=`-joined value forms.
        (
            "aws --region us-east-1 ec2 terminate-instances --instance-ids i-1",
            "terminate",
        ),
        (
            "aws --profile prod dynamodb delete-table --table-name t",
            "table",
        ),
        (
            "aws --output json cloudformation delete-stack --stack-name s",
            "stack",
        ),
        ("aws --region=us-east-1 s3 rb s3://b --force", "bucket"),
        // Multiple stacked globals, mixed forms, still anchor to the service.
        (
            "aws --profile prod --region us-east-1 --output json ec2 terminate-instances --instance-ids i-1",
            "terminate",
        ),
        // A boolean global (no value) between aws and the service.
        (
            "aws --no-cli-pager dynamodb delete-table --table-name t",
            "table",
        ),
        // A global option in front of a catch-all destructive verb.
        (
            "aws --region us-east-1 ec2 delete-vpc --vpc-id vpc-1",
            "destructive",
        ),
        // I1 — IAM inline-policy self-escalation (put-*-policy / create-policy-version)
        (
            "aws iam put-role-policy --role-name r --policy-name p --policy-document file://admin.json",
            "self-escalate",
        ),
        (
            "aws iam put-user-policy --user-name u --policy-name p --policy-document file://admin.json",
            "self-escalate",
        ),
        (
            "aws iam put-group-policy --group-name g --policy-name p --policy-document file://admin.json",
            "self-escalate",
        ),
        (
            "aws iam create-policy-version --policy-arn arn:aws:iam::1:policy/p --policy-document file://admin.json --set-as-default",
            "self-escalate",
        ),
        // IAM self-escalation still caught with a global option in front.
        (
            "aws --profile prod iam put-role-policy --role-name r --policy-name p --policy-document file://admin.json",
            "self-escalate",
        ),
        // sudo-wrapped forms still denied (wrapper peeled before matching)
        (
            "sudo aws ec2 terminate-instances --instance-ids i-1",
            "terminate",
        ),
        // chained after a benign command
        (
            "cd infra && aws dynamodb delete-table --table-name t",
            "table",
        ),
    ];
    for (cmd, needle) in cases {
        let (pack, reason) = deny(&e, cmd);
        assert_eq!(pack, "cloud.aws", "for {cmd:?}");
        assert!(
            reason.contains(needle),
            "reason {reason:?} should mention {needle:?} for {cmd:?}"
        );
    }
}

#[test]
fn allows_safe_aws_commands() {
    let e = engine();
    let allow = [
        // read verbs
        "aws ec2 describe-instances",
        "aws s3 ls",
        "aws s3 ls s3://my-bucket",
        "aws cloudformation describe-stacks",
        "aws rds describe-db-instances",
        "aws dynamodb describe-table --table-name users",
        "aws dynamodb list-tables",
        "aws iam list-roles",
        "aws iam get-role --role-name r",
        "aws organizations list-accounts",
        "aws organizations describe-organization",
        // an RDS delete that keeps a final snapshot is recoverable → allowed
        "aws rds delete-db-instance --db-instance-identifier prod --final-db-snapshot-identifier snap-1",
        "aws rds delete-db-cluster --db-cluster-identifier c --final-db-snapshot-identifier snap-2",
        // "delete" as a substring of a resource NAME / value, not the operation
        "aws ec2 describe-instances --filters Name=tag:Name,Values=delete-me",
        "aws s3 ls s3://delete-me",
        "aws s3 cp file.txt s3://delete-me/file.txt",
        // single-object S3 delete without --recursive is not blanket-blocked
        "aws s3 rm s3://my-bucket/one-object.txt",
        // benign IAM attach (not AdministratorAccess)
        "aws iam attach-role-policy --role-name r --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess",
        // an undelete/restore verb must not trip the delete catch-all
        "aws route53domains list-domains",
        // C1 — benign GLOBAL-flagged reads must still ALLOW (globals tolerated,
        // but a read verb never blocks).
        "aws --region us-east-1 ec2 describe-instances",
        "aws --profile prod s3 ls",
        "aws --output json --region us-east-1 dynamodb list-tables",
        // C2 — routine / recoverable delete verbs the catch-all must NOT block:
        // SQS message-ack (breaks every poller if blocked), tag removal (no data
        // loss), single versioned-object delete (recoverable).
        "aws sqs delete-message --queue-url https://q --receipt-handle abc",
        "aws sqs delete-message-batch --queue-url https://q --entries file://e.json",
        "aws ec2 delete-tags --resources i-0abc --tags Key=env",
        "aws s3api delete-object --bucket b --key path/to/one-object.txt",
        // routine delete verbs stay allowed even with a global option in front
        "aws --region us-east-1 sqs delete-message --queue-url https://q --receipt-handle abc",
        // A value-taking global whose VALUE looks destructive must not let the
        // flag masquerade as the service in the catch-all: these are pure reads.
        "aws --profile delete-me s3 ls",
        "aws --profile force-prod ec2 describe-instances",
        "aws --query terminated ec2 describe-instances",
        "aws --query delete_markers s3api list-object-versions",
        "aws --query terminateProtection ec2 describe-instances",
        "aws --output text --query terminated ec2 describe-instances",
        "aws --region force ec2 describe-instances",
    ];
    for cmd in allow {
        assert!(
            !e.evaluate(cmd).is_deny(),
            "expected ALLOW for {cmd:?}, got DENY"
        );
    }
}

/// The RDS snapshot boundary on its own: identical delete, snapshot flag flips
/// the verdict. The near-miss the spec (§10) calls out explicitly.
#[test]
fn rds_snapshot_boundary() {
    let e = engine();
    assert!(
        e.evaluate("aws rds delete-db-instance --db-instance-identifier prod")
            .is_deny(),
        "un-snapshotted RDS delete must DENY"
    );
    assert!(
        !e.evaluate(
            "aws rds delete-db-instance --db-instance-identifier prod --final-db-snapshot-identifier snap-1"
        )
        .is_deny(),
        "snapshotted RDS delete must ALLOW"
    );
}
