//! Fix round 1 (plan 17, Task 1): over-cap lines report at once, `\r`
//! stripped once, lenient cancel and progress, resource validation.

use std::io::Cursor;

use saiife_mcp::codec::{decode_line, LineReader};
use saiife_mcp::jsonrpc::{Id, INVALID_REQUEST};
use saiife_mcp::types::{CallToolParams, CancelledParams, ResourceContents};
use serde_json::json;

const MAX: usize = 1 << 20;

#[test]
fn over_cap_line_reports_at_once_on_endless_input() {
    // An endless line: the first call must report, not drain forever.
    let r = std::io::BufReader::new(std::io::repeat(b'x'));
    let mut lr = LineReader::new(r, 1000);
    let e = lr.next_message().unwrap().unwrap().unwrap_err();
    assert_eq!(e.error.code, INVALID_REQUEST);

    // The rest of the over-cap line is skipped before the next message,
    // whether its newline is in the same read or a later one.
    let ok = r#"{"jsonrpc":"2.0","method":"a"}"#;
    for cap in [4usize, 16, 4096] {
        let input = format!("{}\n{ok}\n", "y".repeat(200));
        let r = std::io::BufReader::with_capacity(cap, Cursor::new(input.into_bytes()));
        let mut lr = LineReader::new(r, 50);
        assert_eq!(
            lr.next_message().unwrap().unwrap().unwrap_err().error.code,
            INVALID_REQUEST,
            "{cap}"
        );
        assert_eq!(
            lr.next_message().unwrap().unwrap().unwrap().method(),
            Some("a"),
            "{cap}"
        );
        assert!(lr.next_message().unwrap().is_none(), "{cap}");
    }
}

#[test]
fn carriage_return_stripped_once_only() {
    let ok = r#"{"jsonrpc":"2.0","method":"a"}"#;
    assert!(decode_line(format!("{ok}\r").as_bytes(), MAX).is_ok());
    assert!(decode_line(format!("{ok}\r\r").as_bytes(), MAX).is_err());
    let input = format!("{ok}\r\r\n{ok}\r\n");
    let mut lr = LineReader::new(Cursor::new(input.into_bytes()), 1000);
    assert!(lr.next_message().unwrap().unwrap().is_err());
    assert!(lr.next_message().unwrap().unwrap().is_ok());
    assert!(lr.next_message().unwrap().is_none());
}

#[test]
fn cancel_without_request_id_is_readable() {
    let p: CancelledParams = serde_json::from_value(json!({"reason": "x"})).unwrap();
    assert_eq!(p.request_id, None);
    let p: CancelledParams = serde_json::from_value(json!({"requestId": 1.5})).unwrap();
    assert_eq!(p.request_id, None);
    let p: CancelledParams = serde_json::from_value(json!({"requestId": "r"})).unwrap();
    assert_eq!(p.request_id, Some(Id::String("r".into())));
}

#[test]
fn bad_progress_token_is_dropped_not_fatal() {
    for tok in [json!(1.5), json!(null), json!(true), json!({}), json!([1])] {
        let p: CallToolParams =
            serde_json::from_value(json!({"name": "a", "_meta": {"progressToken": tok}})).unwrap();
        assert_eq!(p.meta.unwrap().progress_token, None, "{tok}");
    }
    let p: CallToolParams =
        serde_json::from_value(json!({"name": "a", "_meta": {"progressToken": 7}})).unwrap();
    assert_eq!(p.meta.unwrap().progress_token, Some(Id::from(7i64)));
}

#[test]
fn resource_contents_needs_text_or_blob() {
    let r = |text: Option<&str>, blob: Option<&str>| ResourceContents {
        uri: "saiife://response".into(),
        mime_type: None,
        text: text.map(Into::into),
        blob: blob.map(Into::into),
    };
    assert!(r(Some("t"), None).validate().is_ok());
    assert!(r(None, Some("AA==")).validate().is_ok());
    assert!(r(None, None).validate().is_err());
    assert!(r(Some("t"), Some("AA==")).validate().is_err());
}
