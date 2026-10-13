//! Golden corpus for `iac.terraform` (opt-in — must be enabled explicitly).
//!
//! The plan/apply split *is* the human approval gate, so these rules exist to
//! make that gate unbypassable: `terraform destroy`, bare `terraform apply`
//! (which re-plans and applies blind), `-auto-approve`, `state rm/mv`, and
//! `force-unlock` are denied; `terraform apply <planfile>` and every read-only
//! verb must pass. The keystone is the bare-apply-vs-planfile boundary, tested
//! explicitly below.

use saiifeguard::builtins::builtin_packs;
use saiifeguard::engine::{Decision, Engine};
use saiifeguard::profile::select_active;

fn engine() -> Engine {
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    Engine::new(select_active(packs, &["iac.terraform".to_string()]))
}

fn deny(e: &Engine, cmd: &str) -> (String, String) {
    match e.evaluate(cmd) {
        Decision::Deny { pack, reason, .. } => (pack, reason),
        other => panic!("expected DENY for {cmd:?}, got {other:?}"),
    }
}

#[test]
fn denies_destructive_terraform_commands() {
    let e = engine();
    // (command, substring the reason must contain — proves the class is named)
    let cases = [
        // destroy — bare and via `apply -destroy`
        ("terraform destroy", "tears down"),
        ("terraform destroy -auto-approve", "tears down"),
        ("terraform destroy -target=aws_instance.foo", "tears down"),
        ("terraform apply -destroy", "tears down"),
        ("terraform apply -destroy -auto-approve", "tears down"),
        ("terraform apply --destroy", "tears down"),
        // bare apply — no saved plan file (the keystone rule)
        ("terraform apply", "blind"),
        ("terraform apply -input=false", "blind"),
        ("terraform -chdir=infra apply", "blind"),
        // I2 — a value-taking flag whose value is a SEPARATE token must not be
        // mistaken for a positional plan file: these are all still BARE applies.
        ("terraform apply -var region=us-east-1", "blind"),
        ("terraform apply -var name=val -var other=x", "blind"),
        ("terraform apply -var-file prod.tfvars", "blind"),
        ("terraform apply -target aws_instance.foo", "blind"),
        ("terraform apply -replace aws_instance.foo", "blind"),
        ("terraform apply -input=false -var region=us-east-1", "blind"),
        // auto-approve, anywhere in argv
        ("terraform apply -auto-approve", "confirmation"),
        ("terraform apply --auto-approve", "confirmation"),
        ("terraform apply -input=false -auto-approve", "confirmation"),
        ("terraform apply -auto-approve plan.tfplan", "confirmation"),
        // state rm / mv
        ("terraform state rm aws_instance.foo", "state"),
        ("terraform state mv aws_instance.a aws_instance.b", "state"),
        // force-unlock
        ("terraform force-unlock 1a2b3c", "lock"),
        // sudo-wrapped forms still denied (wrapper is peeled before matching)
        ("sudo terraform destroy", "tears down"),
        ("sudo terraform apply", "blind"),
        // chained after a benign command
        ("cd infra && terraform destroy", "tears down"),
    ];
    for (cmd, needle) in cases {
        let (pack, reason) = deny(&e, cmd);
        assert_eq!(pack, "iac.terraform", "for {cmd:?}");
        assert!(
            reason.contains(needle),
            "reason {reason:?} should mention {needle:?} for {cmd:?}"
        );
    }
}

#[test]
fn allows_safe_terraform_commands() {
    let e = engine();
    let allow = [
        "terraform plan",
        "terraform plan -out=plan.tfplan",
        "terraform output",
        "terraform output -json",
        "terraform init",
        "terraform validate",
        "terraform fmt",
        "terraform show plan.tfplan",
        "terraform version",
        // state read verbs — only rm/mv are destructive
        "terraform state list",
        "terraform state show aws_instance.foo",
        "terraform state pull",
        // a resource literally named to look like a destructive verb
        "terraform state show aws_instance.delete_me",
        "terraform plan -target=aws_instance.destroy_me",
        // I2 — a reviewed plan file after a value-taking flag is still a
        // positional plan file → ALLOW (the value-flag consumes only its own
        // value token, the .tfplan remains positional and stops the keystone).
        "terraform apply -var region=us-east-1 plan.tfplan",
        "terraform apply -target aws_instance.foo plan.tfplan",
    ];
    for cmd in allow {
        assert!(
            !e.evaluate(cmd).is_deny(),
            "expected ALLOW for {cmd:?}, got DENY"
        );
    }
}

/// The keystone boundary, stated on its own: bare `terraform apply` (no saved
/// plan-file argument) MUST block; `terraform apply <planfile>` MUST NOT. When
/// the planfile detection is ambiguous we err toward allow (spec §7), so a
/// positional argument is always treated as a plan file.
#[test]
fn apply_planfile_vs_bare_boundary() {
    let e = engine();

    // Bare apply — no positional plan file → DENY. Includes value-taking flags
    // whose value is a separate token (the I2 bypass): still bare.
    for cmd in [
        "terraform apply",
        "terraform apply -input=false",
        "terraform apply -var region=us-east-1",
        "terraform apply -target aws_instance.foo",
    ] {
        assert!(e.evaluate(cmd).is_deny(), "bare apply must DENY: {cmd:?}");
    }

    // Apply with a saved plan file (a positional, non-flag argument) → ALLOW.
    for cmd in [
        "terraform apply plan.tfplan",
        "terraform apply ./plans/prod.tfplan",
        "terraform apply -input=false plan.tfplan",
        "terraform -chdir=infra apply infra.tfplan",
        "terraform apply out",
        "terraform apply -var region=us-east-1 plan.tfplan",
    ] {
        assert!(
            !e.evaluate(cmd).is_deny(),
            "apply <planfile> must ALLOW: {cmd:?}"
        );
    }
}
