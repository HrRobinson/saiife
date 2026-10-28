//! The five cloud manifests (plan 15, Task 8): aws-s3, aws-sts,
//! gcp-storage, azure-arm and azure-blob. One golden request per operation,
//! with a fixed clock and fake credentials. Offline.
//!
//! The AWS goldens hold the full SigV4 `Authorization`, from
//! `sigv4::sign` with `for_service(params.region, auth.service)`, as the
//! sign mode does. The GCP and Azure goldens show where the minted bearer
//! token goes. Set `SAIIFE_BLESS_GOLDEN=1` to rewrite the golden files.

use bytes::Bytes;
use http::header::{HeaderValue, AUTHORIZATION};
use saiife_broker::cloud::sigv4::{for_service, sign, AwsCreds};
use saiife_broker::manifest::{builtin, qualifier_for, Manifest, OpKind};
use saiife_broker::params::validate;
use saiife_broker::request::{build, AuthMaterial, Built};
use saiife_broker::resolve::named;
use std::collections::BTreeMap;
use time::OffsetDateTime;
use zeroize::Zeroizing;

const S3: &str = include_str!("../connectors/aws-s3.toml");
const STS: &str = include_str!("../connectors/aws-sts.toml");
const GCS: &str = include_str!("../connectors/gcp-storage.toml");
const ARM: &str = include_str!("../connectors/azure-arm.toml");
const BLOB: &str = include_str!("../connectors/azure-blob.toml");

const IDS: [&str; 5] = [
    "aws-s3",
    "aws-sts",
    "gcp-storage",
    "azure-arm",
    "azure-blob",
];

/// The AWS docs' example key pair, built at runtime (no key-shaped literal
/// in the tree).
const ACCESS_KEY: &str = concat!("AKID", "EXAMPLE");
const SECRET_KEY: &str = concat!("wJalrXUtnFEMI/K7MDENG+", "bPxRfiCYEXAMPLEKEY");
const TOKEN: &str = concat!("fake-", "minted-", "access-token");

/// An operation id, the call params and the body.
type Case<'a> = (&'a str, Vec<(&'a str, &'a str)>, Option<&'a str>);

const SUB: &str = "00000000-1111-2222-3333-444444444444";

fn manifest(text: &str) -> Manifest {
    Manifest::parse(text).expect("manifest parses")
}

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// 2026-10-28T12:34:56Z.
fn clock() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_793_190_896).unwrap()
}

fn creds() -> AwsCreds {
    AwsCreds {
        access_key_id: Zeroizing::new(ACCESS_KEY.to_string()),
        secret_access_key: Zeroizing::new(SECRET_KEY.to_string()),
        session_token: None,
    }
}

/// What an agent may try to send: only `Content-Type` and `Range` survive.
fn agent_headers(body: bool) -> Vec<(String, String)> {
    let mut h: Vec<(String, String)> = [
        ("Authorization", "Bearer agent-guess"),
        ("Host", "evil.test"),
        ("Cookie", "a=b"),
        ("x-amz-copy-source", "/other-bucket/secret"),
        ("x-amz-acl", "public-read"),
        (
            "x-amz-target",
            "AWSSecurityTokenServiceV20110615.AssumeRole",
        ),
        ("x-amz-server-side-encryption", "aws:kms"),
        ("x-amz-date", "20000101T000000Z"),
        ("x-amz-security-token", "agent"),
        ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
        (
            "x-ms-copy-source",
            "https://other.blob.core.windows.net/c/b",
        ),
        ("x-ms-version", "2009-09-19"),
        ("x-ms-blob-type", "AppendBlob"),
        ("x-ms-delete-snapshots", "include"),
        ("Range", "bytes=0-99"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    if body {
        h.push((
            "Content-Type".to_string(),
            "application/octet-stream".to_string(),
        ));
    }
    h
}

/// Validates `call` and builds the request the way the pipeline does, then
/// adds the credential the way the sign mode does.
fn built(
    m: &Manifest,
    op_id: &str,
    svc: &[(&str, &str)],
    call: &[(&str, &str)],
    body: Option<&str>,
) -> Built {
    let op = named(m, op_id).unwrap_or_else(|| panic!("{}: no {op_id}", m.id));
    let params =
        validate(op, &map(call), &BTreeMap::new()).unwrap_or_else(|e| panic!("{op_id}: {e}"));
    let auth = AuthMaterial::from_spec(&m.auth[0], BTreeMap::new());
    let mut b = build(
        m,
        op,
        &map(svc),
        &params,
        &agent_headers(body.is_some()),
        body.map(|b| Bytes::from(b.to_string())),
        &auth,
    )
    .unwrap_or_else(|e| panic!("{op_id}: {e}"));
    let spec = &m.auth[0];
    match spec.kind.as_str() {
        "aws_sigv4" => {
            let region = map(svc)["region"].clone();
            let o = for_service(&region, spec.service.as_deref().unwrap());
            sign(&mut b, &creds(), &o, clock()).unwrap();
        }
        "gcp_sa" | "azure_sp" => {
            assert!(b.headers.get(AUTHORIZATION).is_none());
            b.headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {TOKEN}")).unwrap(),
            );
        }
        k => panic!("{}: unexpected auth kind {k}", m.id),
    }
    b
}

fn render(b: &Built) -> String {
    let mut lines: Vec<String> = b
        .headers
        .iter()
        .map(|(k, v)| format!("{}: {}", k.as_str(), v.to_str().unwrap()))
        .collect();
    lines.sort();
    let mut out = format!("{} {}\n", b.method, b.uri);
    for l in lines {
        out.push_str(&l);
        out.push('\n');
    }
    if let Some(body) = &b.body {
        out.push('\n');
        out.push_str(std::str::from_utf8(body).unwrap());
        out.push('\n');
    }
    out
}

fn check_golden(name: &str, b: &Built) {
    let p = format!(
        "{}/tests/golden/cloud/{name}.txt",
        env!("CARGO_MANIFEST_DIR")
    );
    let got = render(b);
    if std::env::var_os("SAIIFE_BLESS_GOLDEN").is_some() {
        std::fs::write(&p, &got).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"));
    assert_eq!(got, want, "golden {name}");
}

const S3_SVC: [(&str, &str); 1] = [("region", "eu-west-1")];
const STS_SVC: [(&str, &str); 1] = [("region", "us-east-1")];
const BLOB_SVC: [(&str, &str); 1] = [("account", "acmedata")];

#[test]
fn cloud_manifests_are_builtin() {
    for id in IDS {
        assert!(builtin().iter().any(|m| m.id == id), "{id} is not built in");
    }
    for (text, id) in [
        (S3, "aws-s3"),
        (STS, "aws-sts"),
        (GCS, "gcp-storage"),
        (ARM, "azure-arm"),
        (BLOB, "azure-blob"),
    ] {
        let m = manifest(text);
        assert_eq!(m.id, id);
        assert_eq!(m.auth.len(), 1, "{id}: one auth entry");
    }
    assert_eq!(manifest(S3).auth[0].service.as_deref(), Some("s3"));
    assert_eq!(manifest(STS).auth[0].service.as_deref(), Some("sts"));
    assert_eq!(
        manifest(GCS).auth[0].scope.as_deref(),
        Some("https://www.googleapis.com/auth/devstorage.read_write")
    );
    assert_eq!(
        manifest(ARM).auth[0].scope.as_deref(),
        Some("https://management.azure.com/.default")
    );
    assert_eq!(
        manifest(BLOB).auth[0].scope.as_deref(),
        Some("https://storage.azure.com/.default")
    );
}

#[test]
fn cloud_ops_have_iam_action() {
    let want: &[(&str, &str, &str, &str)] = &[
        ("aws-s3", "s3.list_objects", "s3:read", "s3:ListBucket"),
        ("aws-s3", "s3.get_object", "s3:read", "s3:GetObject"),
        ("aws-s3", "s3.head_object", "s3:read", "s3:GetObject"),
        ("aws-s3", "s3.put_object", "s3:write", "s3:PutObject"),
        ("aws-s3", "s3.delete_object", "s3:delete", "s3:DeleteObject"),
        (
            "aws-sts",
            "sts.get_caller_identity",
            "sts:read",
            "sts:GetCallerIdentity",
        ),
        (
            "gcp-storage",
            "storage.objects.list",
            "storage:read",
            "storage.objects.list",
        ),
        (
            "gcp-storage",
            "storage.objects.get",
            "storage:read",
            "storage.objects.get",
        ),
        (
            "gcp-storage",
            "storage.objects.download",
            "storage:read",
            "storage.objects.get",
        ),
        (
            "gcp-storage",
            "storage.objects.insert",
            "storage:write",
            "storage.objects.create",
        ),
        (
            "gcp-storage",
            "storage.objects.delete",
            "storage:delete",
            "storage.objects.delete",
        ),
        (
            "azure-arm",
            "resourcegroups.list",
            "resourcegroups:read",
            "Microsoft.Resources/subscriptions/resourceGroups/read",
        ),
        (
            "azure-arm",
            "resources.list",
            "resources:read",
            "Microsoft.Resources/subscriptions/resources/read",
        ),
        (
            "azure-arm",
            "vms.list",
            "vms:read",
            "Microsoft.Compute/virtualMachines/read",
        ),
        (
            "azure-arm",
            "vms.restart",
            "vms:write",
            "Microsoft.Compute/virtualMachines/restart/action",
        ),
        (
            "azure-blob",
            "blobs.list",
            "blobs:read",
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        ),
        (
            "azure-blob",
            "blobs.get",
            "blobs:read",
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        ),
        (
            "azure-blob",
            "blobs.put",
            "blobs:write",
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
        ),
        (
            "azure-blob",
            "blobs.delete",
            "blobs:delete",
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
        ),
    ];
    let mut total = 0;
    for m in builtin().iter().filter(|m| IDS.contains(&m.id.as_str())) {
        for op in &m.operation {
            assert!(
                op.iam_action.is_some(),
                "{}: {} has no iam_action",
                m.id,
                op.id
            );
            let w = want
                .iter()
                .find(|w| w.0 == m.id && w.1 == op.id)
                .unwrap_or_else(|| panic!("{}: unexpected operation {}", m.id, op.id));
            assert_eq!(op.capability, w.2, "{}", op.id);
            assert_eq!(op.iam_action.as_deref(), Some(w.3), "{}", op.id);
            total += 1;
        }
    }
    assert_eq!(total, want.len());
}

/// Every read is a GET or HEAD, every DELETE is a delete op (so
/// `deletes_per_day` counts it) and every other change is a write. The
/// docs put both kinds under `ask`.
#[test]
fn cloud_changes_are_writes() {
    for m in builtin().iter().filter(|m| IDS.contains(&m.id.as_str())) {
        for op in &m.operation {
            let want = match op.method.as_str() {
                "GET" | "HEAD" => OpKind::Read,
                // Counted by `deletes_per_day`.
                "DELETE" => OpKind::Delete,
                _ => OpKind::Write,
            };
            assert_eq!(op.kind, want, "{}: {}", m.id, op.id);
        }
    }
}

/// The SigV4 signer signs every header present and policy does not see
/// headers: the agent may set only `Content-Type` and `Range`.
#[test]
fn no_action_changing_request_headers() {
    for m in builtin().iter().filter(|m| IDS.contains(&m.id.as_str())) {
        for h in &m.request_headers {
            assert!(
                h.eq_ignore_ascii_case("content-type") || h.eq_ignore_ascii_case("range"),
                "{}: request header {h} is not allowed on a cloud manifest",
                m.id
            );
        }
        assert!(m.headers.is_empty(), "{}: no manifest-wide headers", m.id);
    }
}

#[test]
fn cloud_qualifiers() {
    let s3 = manifest(S3);
    let p = map(&[("bucket", "acme-logs"), ("key", "2026/10/a.json")]);
    for op in [
        "s3.get_object",
        "s3.head_object",
        "s3.put_object",
        "s3.delete_object",
    ] {
        assert_eq!(
            qualifier_for(named(&s3, op).unwrap(), &p).as_deref(),
            Some("arn:aws:s3:::acme-logs/2026/10/a.json"),
            "{op}"
        );
    }
    assert_eq!(
        qualifier_for(named(&s3, "s3.list_objects").unwrap(), &p).as_deref(),
        Some("arn:aws:s3:::acme-logs")
    );
    let gcs = manifest(GCS);
    let p = map(&[
        ("bucket", "acme"),
        ("object", "a/b.txt"),
        ("name", "a/c.txt"),
    ]);
    assert_eq!(
        qualifier_for(named(&gcs, "storage.objects.download").unwrap(), &p).as_deref(),
        Some("projects/_/buckets/acme/objects/a/b.txt")
    );
    assert_eq!(
        qualifier_for(named(&gcs, "storage.objects.insert").unwrap(), &p).as_deref(),
        Some("projects/_/buckets/acme/objects/a/c.txt")
    );
    let arm = manifest(ARM);
    let p = map(&[
        ("subscription_id", SUB),
        ("resource_group", "web"),
        ("vm_name", "vm1"),
    ]);
    assert_eq!(
        qualifier_for(named(&arm, "vms.restart").unwrap(), &p).unwrap(),
        format!("/subscriptions/{SUB}/resourceGroups/web/providers/Microsoft.Compute/virtualMachines/vm1")
    );
    let blob = manifest(BLOB);
    let p = map(&[("container", "logs"), ("blob", "a/b.txt")]);
    assert_eq!(
        qualifier_for(named(&blob, "blobs.delete").unwrap(), &p).as_deref(),
        Some("logs/a/b.txt")
    );
}

/// Azure names are case-insensitive and `allow` compares case exactly: only
/// the lower-case spelling is accepted, so each resource has one qualifier.
#[test]
fn azure_names_lower_case_only() {
    let arm = manifest(ARM);
    let op = named(&arm, "vms.restart").unwrap();
    let ok = [
        ("subscription_id", SUB),
        ("resource_group", "web"),
        ("vm_name", "vm1"),
    ];
    assert!(validate(op, &map(&ok), &BTreeMap::new()).is_ok());
    for (k, v) in [
        ("subscription_id", "00000000-1111-2222-3333-44444444444A"),
        ("resource_group", "Web"),
        ("vm_name", "VM1"),
    ] {
        let mut p = map(&ok);
        p.insert(k.to_string(), v.to_string());
        assert!(validate(op, &p, &BTreeMap::new()).is_err(), "{k}={v}");
    }
}

#[test]
fn sts_get_caller_identity_path_is_slash() {
    let m = manifest(STS);
    let b = built(&m, "sts.get_caller_identity", &STS_SVC, &[], None);
    assert_eq!(b.uri.host(), Some("sts.us-east-1.amazonaws.com"));
    assert_eq!(b.uri.path(), "/");
    assert_eq!(
        b.uri.query(),
        Some("Action=GetCallerIdentity&Version=2011-06-15")
    );
    // The agent cannot pick another action.
    let op = named(&m, "sts.get_caller_identity").unwrap();
    assert!(validate(op, &map(&[("Action", "AssumeRole")]), &BTreeMap::new()).is_err());
    assert!(b.headers.get("x-amz-target").is_none());
    check_golden("sts_get_caller_identity", &b);
}

#[test]
fn s3_goldens() {
    let m = manifest(S3);
    let key = [("bucket", "acme-logs"), ("key", "2026/10/report.json")];
    let cases: [Case; 5] = [
        (
            "s3.list_objects",
            vec![
                ("bucket", "acme-logs"),
                ("prefix", "2026/10/"),
                ("max-keys", "100"),
            ],
            None,
        ),
        ("s3.get_object", key.to_vec(), None),
        ("s3.head_object", key.to_vec(), None),
        ("s3.put_object", key.to_vec(), Some("{\"ok\":true}")),
        ("s3.delete_object", key.to_vec(), None),
    ];
    for (op, call, body) in cases {
        let b = built(&m, op, &S3_SVC, &call, body);
        assert_eq!(b.uri.host(), Some("s3.eu-west-1.amazonaws.com"));
        for banned in [
            "x-amz-copy-source",
            "x-amz-acl",
            "x-amz-target",
            "x-amz-server-side-encryption",
            "cookie",
        ] {
            assert!(b.headers.get(banned).is_none(), "{op}: {banned}");
        }
        check_golden(&op.replace('.', "_"), &b);
    }
}

/// Decision 4 and review focus 1: the bytes on the wire are the signed
/// canonical URI, and `+` is never sent as a space.
#[test]
fn s3_get_object_awkward_key_golden() {
    let m = manifest(S3);
    let key = "dir one/a b+c%d~e=f&g!*'()\u{e9}.txt";
    let b = built(
        &m,
        "s3.get_object",
        &S3_SVC,
        &[("bucket", "acme-logs"), ("key", key)],
        None,
    );
    assert_eq!(
        b.uri.path(),
        "/acme-logs/dir%20one/a%20b%2Bc%25d~e%3Df%26g%21%2A%27%28%29%C3%A9.txt"
    );
    let qual = qualifier_for(
        named(&m, "s3.get_object").unwrap(),
        &map(&[("bucket", "acme-logs"), ("key", key)]),
    );
    assert_eq!(qual.unwrap(), format!("arn:aws:s3:::acme-logs/{key}"));
    check_golden("s3_get_object_awkward_key", &b);
}

#[test]
fn gcs_goldens() {
    let m = manifest(GCS);
    let obj = [("bucket", "acme-data"), ("object", "2026/10/report.json")];
    let cases: [Case; 5] = [
        (
            "storage.objects.list",
            vec![
                ("bucket", "acme-data"),
                ("prefix", "2026/"),
                ("maxResults", "50"),
            ],
            None,
        ),
        ("storage.objects.get", obj.to_vec(), None),
        ("storage.objects.download", obj.to_vec(), None),
        (
            "storage.objects.insert",
            vec![("bucket", "acme-data"), ("name", "2026/10/new.json")],
            Some("{\"ok\":true}"),
        ),
        ("storage.objects.delete", obj.to_vec(), None),
    ];
    for (op, call, body) in cases {
        let b = built(&m, op, &[], &call, body);
        if op != "storage.objects.list" {
            assert!(
                b.uri.to_string().contains("2026%2F10%2F"),
                "{op}: {}",
                b.uri
            );
        }
        check_golden(&op.replace('.', "_"), &b);
    }
}

#[test]
fn azure_arm_goldens() {
    let m = manifest(ARM);
    let sub = [("subscription_id", SUB)];
    let cases: [(&str, Vec<(&str, &str)>); 4] = [
        (
            "resourcegroups.list",
            vec![("subscription_id", SUB), ("$top", "10")],
        ),
        ("resources.list", sub.to_vec()),
        ("vms.list", sub.to_vec()),
        (
            "vms.restart",
            vec![
                ("subscription_id", SUB),
                ("resource_group", "web"),
                ("vm_name", "vm1"),
            ],
        ),
    ];
    for (op, call) in cases {
        let b = built(&m, op, &[], &call, None);
        assert_eq!(b.uri.host(), Some("management.azure.com"));
        assert!(b.uri.query().unwrap().contains("api-version="), "{op}");
        check_golden(&format!("azure_{}", op.replace('.', "_")), &b);
    }
}

#[test]
fn azure_blob_goldens() {
    let m = manifest(BLOB);
    let blob = [("container", "logs"), ("blob", "2026/10/report.json")];
    let cases: [Case; 4] = [
        (
            "blobs.list",
            vec![("container", "logs"), ("prefix", "2026/")],
            None,
        ),
        ("blobs.get", blob.to_vec(), None),
        ("blobs.put", blob.to_vec(), Some("{\"ok\":true}")),
        ("blobs.delete", blob.to_vec(), None),
    ];
    for (op, call, body) in cases {
        let b = built(&m, op, &BLOB_SVC, &call, body);
        assert_eq!(b.uri.host(), Some("acmedata.blob.core.windows.net"));
        // The manifest's version wins over the agent's.
        assert_eq!(b.headers["x-ms-version"], "2026-04-06", "{op}");
        assert!(b.headers.get("x-ms-copy-source").is_none());
        assert!(b.headers.get("x-ms-delete-snapshots").is_none());
        let blob_type = b.headers.get("x-ms-blob-type").map(|v| v.to_str().unwrap());
        assert_eq!(
            blob_type,
            (op == "blobs.put").then_some("BlockBlob"),
            "{op}"
        );
        check_golden(&format!("azure_{}", op.replace('.', "_")), &b);
    }
}

/// A GCS `nextPageToken` is standard base64: `+`, `/` and `=` are sent
/// percent-encoded, never as a space.
#[test]
fn gcs_page_token_plus_encoded() {
    let m = manifest(GCS);
    let b = built(
        &m,
        "storage.objects.list",
        &[],
        &[("bucket", "acme-data"), ("pageToken", "Cg+a/b==")],
        None,
    );
    assert_eq!(b.uri.query(), Some("pageToken=Cg%2Ba%2Fb%3D%3D"));
}
