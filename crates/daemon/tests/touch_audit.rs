//! Audit-chain compatibility of the touch records (plan 26, Task 9; Review
//! Focus 5): a v2 chain followed by `touch_enrolled` and an `approved`
//! record carrying `touch` evidence still verifies, and the evidence reads
//! back byte for byte.

use std::collections::BTreeMap;
use std::path::Path;

use saiife_audit::chain::append_chained;
use saiife_audit::{DecisionKind, NewRecord, Record};
use saiife_daemon::approvals::record_with_touch;
use saiife_daemon::touch_ops::enrolled_record;
use saiife_touch::soft::SoftAuthenticator;
use saiife_touch::{challenge, verify, ActionRecord, TouchClass, TouchEvidence, LOCAL_RP_ID};
use serde_json::{json, Value};

const NOW: u64 = 1_800_000_000;

fn base(kind: &str, input: &str, decision: DecisionKind) -> Record {
    let mut r = Record::new(
        NewRecord {
            agent: "",
            project: "",
            session: None,
            tool: kind,
            input,
            decision,
            pack: None,
            rule: None,
            reason: None,
            mode: "locked",
            policy: None,
            permission_mode: None,
        },
        "0.2.0",
    );
    r.kind = Some(kind.into());
    r.uid = Some(999);
    r.user = Some("saiife".into());
    r
}

/// A v2 `approval` record of request `id` with `action`.
fn approval(id: u64, action: &str, decision: DecisionKind) -> Record {
    let mut r = base("approval", "s3_ask s3.put_object", decision);
    r.uid = Some(1000);
    r.user = Some("agent".into());
    r.agent = "claude".into();
    r.project = "/p".into();
    for (k, v) in [
        ("action", json!(action)),
        ("id", json!(id)),
        ("approval", json!(id)),
        ("type", json!("connector")),
        ("service", json!("s3_ask")),
        ("operation", json!("s3.put_object")),
    ] {
        r.extra.insert(k.into(), v);
    }
    r
}

/// A touch over action `id` of class deploy, verified as the daemon does.
fn evidence(soft: &SoftAuthenticator, id: u64) -> TouchEvidence {
    let cred = soft.credential(LOCAL_RP_ID, 1000, "key");
    let mut fields = BTreeMap::new();
    fields.insert("type".into(), "connector".into());
    fields.insert("service".into(), "s3_ask".into());
    fields.insert("operation".into(), "s3.put_object".into());
    fields.insert("project".into(), "/p".into());
    let a = ActionRecord {
        instance_id: [3; 16],
        request_id: id,
        class: TouchClass::Deploy,
        summary: format!("#{id} s3_ask s3.put_object"),
        fields,
        nonce: [9; 32],
        expires_at: NOW + 300,
    };
    let asr = soft.assert_ctap(LOCAL_RP_ID, &challenge(&a));
    verify(&[cred], &a, &asr, LOCAL_RP_ID, NOW).unwrap()
}

/// The `touch_enrolled` record of `soft`'s credential, built by the
/// daemon's own `enrolled_record`.
fn enrolled(soft: &SoftAuthenticator) -> Record {
    let mut r = base("touch", "enrol key", DecisionKind::Allow);
    r.extra.insert("by_uid".into(), json!(1000));
    enrolled_record(r, &soft.credential(LOCAL_RP_ID, 1000, "key"), "host")
}

fn lines(dir: &Path) -> Vec<String> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .collect();
    files.sort();
    files
        .iter()
        .flat_map(|f| {
            std::fs::read_to_string(f)
                .unwrap()
                .lines()
                .map(String::from)
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn old_chain_with_touch_records_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    // A v2 install: three plain approval records.
    append_chained(d, approval(1, "created", DecisionKind::Ask)).unwrap();
    append_chained(d, approval(1, "approved", DecisionKind::Approved)).unwrap();
    append_chained(d, approval(2, "rejected", DecisionKind::Rejected)).unwrap();
    assert_eq!(saiife_audit::verify::verify(d).exit_code(), 0);

    // Upgraded: a device is enrolled and approves request 3 with a touch.
    let soft = SoftAuthenticator::new_es256();
    append_chained(d, enrolled(&soft)).unwrap();
    let ev = evidence(&soft, 3);
    let rec = record_with_touch(approval(3, "approved", DecisionKind::Approved), &ev);
    append_chained(d, rec).unwrap();

    let report = saiife_audit::verify::verify(d);
    assert_eq!(report.exit_code(), 0, "{report:?}");

    // The touch object reads back byte-identical.
    let want = serde_json::to_string(&ev.to_audit()).unwrap();
    let all = lines(d);
    let line = all
        .iter()
        .find(|l| l.contains("\"touch\":"))
        .expect("the approved record with touch");
    assert!(line.contains(&format!("\"touch\":{want}")), "{line}");
    let back: Value = serde_json::from_str(line).unwrap();
    assert_eq!(serde_json::to_string(&back["touch"]).unwrap(), want);
    assert_eq!(back["touch"], ev.to_audit());
    // And it still re-verifies against the enrolled credential.
    let cred = soft.credential(LOCAL_RP_ID, 1000, "key");
    assert_eq!(saiife_touch::reverify(&back["touch"], &cred), Ok(()));
    // Old and new records are all there.
    let e: Value = all
        .iter()
        .find(|l| l.contains("\"touch_enrolled\""))
        .map(|l| serde_json::from_str(l).unwrap())
        .expect("the touch_enrolled record");
    assert_eq!(e["kind"], "touch");
    assert_eq!(e["cred_kind"], "fido2");
    assert_eq!(e["approved_by"], "host");
    assert_eq!(all.iter().filter(|l| l.contains("\"approval\"")).count(), 4);
}

#[test]
fn touch_record_size() {
    for soft in [
        SoftAuthenticator::new_es256(),
        SoftAuthenticator::new_ed25519(),
    ] {
        let ev = evidence(&soft, 42);
        let rec = record_with_touch(approval(42, "approved", DecisionKind::Approved), &ev);
        let n = serde_json::to_vec(&rec).unwrap().len();
        assert!(n < 4096, "{n} bytes");
    }
}
