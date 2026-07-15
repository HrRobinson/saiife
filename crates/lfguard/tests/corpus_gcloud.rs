//! Golden corpus for `cloud.gcloud` (opt-in — must be enabled explicitly).

use lfguard::builtins::builtin_packs;
use lfguard::engine::{Decision, Engine};
use lfguard::profile::select_active;

fn engine() -> Engine {
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    Engine::new(select_active(packs, &["cloud.gcloud".to_string()]))
}

fn deny(e: &Engine, cmd: &str) -> (String, String) {
    match e.evaluate(cmd) {
        Decision::Deny { pack, reason, .. } => (pack, reason),
        other => panic!("expected DENY for {cmd:?}, got {other:?}"),
    }
}

#[test]
fn denies_destructive_gcloud_commands() {
    let e = engine();
    // (command, substring the reason must contain — proves resource class named)
    let cases = [
        ("gcloud projects delete my-proj", "project"),
        (
            "gcloud projects remove-iam-policy-binding p --member=user:x --role=roles/owner",
            "IAM",
        ),
        ("gcloud sql instances delete db1", "Cloud SQL"),
        (
            "gcloud compute instances delete vm1 --zone us-central1-a",
            "Compute Engine",
        ),
        ("gcloud storage buckets delete gs://my-bucket", "bucket"),
        ("gsutil rm -r gs://my-bucket", "recursively"),
        ("gcloud storage rm --recursive gs://b/data", "recursively"),
        (
            "gcloud kms keys destroy k --keyring r --location global",
            "KMS",
        ),
        (
            "gcloud iam service-accounts delete sa@p.iam.gserviceaccount.com",
            "delete",
        ),
        ("sudo gcloud projects delete p", "project"),
        // I2: gsutil bucket removal was previously unguarded.
        ("gsutil rb gs://x", "bucket"),
        ("gsutil rb -f gs://x", "bucket"),
        ("sudo gsutil rb gs://my-bucket", "bucket"),
    ];
    for (cmd, needle) in cases {
        let (pack, reason) = deny(&e, cmd);
        assert_eq!(pack, "cloud.gcloud", "for {cmd:?}");
        assert!(
            reason.contains(needle),
            "reason {reason:?} should mention {needle:?} for {cmd:?}"
        );
    }
}

#[test]
fn allows_safe_gcloud_commands() {
    let e = engine();
    let allow = [
        "gcloud projects list",
        "gcloud compute instances list",
        "gcloud sql instances describe db1",
        "gcloud storage ls gs://my-bucket",
        "gsutil ls gs://my-bucket",
        "gsutil cp local.txt gs://my-bucket/",
        "gcloud auth login",
        "gcloud config set project my-proj",
        "gcloud projects add-iam-policy-binding p --member=user:x --role=roles/viewer",
        "gcloud storage cp a.txt gs://b/",
        // I1: "delete" as a substring of a resource NAME must not trigger
        // the catch-all — only "delete" as its own verb token should.
        "gcloud compute instances describe delete-me-vm",
        "gcloud compute instances list --filter=name:delete-me",
        "gcloud sql instances describe delete-later-db",
        "gcloud compute instances create my-delete-vm",
        "gcloud iam service-accounts describe delete-sa@p.iam.gserviceaccount.com",
    ];
    for cmd in allow {
        assert!(
            !e.evaluate(cmd).is_deny(),
            "expected ALLOW for {cmd:?}, got DENY"
        );
    }
}

#[test]
fn catch_all_still_denies_delete_as_the_actual_verb() {
    let e = engine();
    // Not covered by a specific rule (no dedicated iam service-accounts
    // rule), so this exercises the generic catch-all specifically.
    let (pack, reason) = deny(
        &e,
        "gcloud iam service-accounts delete sa@p.iam.gserviceaccount.com",
    );
    assert_eq!(pack, "cloud.gcloud");
    assert!(reason.contains("delete"));
}
