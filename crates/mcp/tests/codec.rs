//! JSON-RPC 2.0 codec, MCP types and version negotiation (plan 17, Task 1).

use std::io::Cursor;

use saiife_mcp::codec::{decode_line, encode, LineReader, MAX_DEPTH};
use saiife_mcp::jsonrpc::{
    Id, Message, RpcError, INTERNAL_ERROR, INVALID_PARAMS, INVALID_REQUEST, METHOD_NOT_FOUND,
    PARSE_ERROR,
};
use saiife_mcp::types::{CallToolParams, CallToolResult, Content, ResourceContents, Tool};
use saiife_mcp::version::{negotiate, PREFERRED, SUPPORTED};
use serde_json::{json, Value};

const MAX: usize = 1 << 20;

fn code(line: &str) -> i64 {
    decode_line(line.as_bytes(), MAX).unwrap_err().error.code
}

#[test]
fn request_notification_response_roundtrip() {
    let msgs = vec![
        Message::Request {
            id: Id::Number(7.into()),
            method: "tools/call".into(),
            params: Some(json!({"name": "x", "arguments": {"a": 1}})),
        },
        Message::Request {
            id: Id::String("abc".into()),
            method: "ping".into(),
            params: None,
        },
        Message::Notification {
            method: "notifications/initialized".into(),
            params: None,
        },
        Message::Notification {
            method: "notifications/progress".into(),
            params: Some(json!({"progressToken": "t", "progress": 1})),
        },
        Message::Response {
            id: Id::Number(7.into()),
            result: json!({"tools": []}),
        },
        Message::Error {
            id: Some(Id::String("abc".into())),
            error: RpcError::method_not_found("nope"),
        },
        Message::Error {
            id: None,
            error: RpcError::parse_error(),
        },
    ];
    for m in msgs {
        let line = encode(&m);
        assert!(line.ends_with('\n'), "{line:?}");
        assert_eq!(line.matches('\n').count(), 1, "{line:?}");
        let back = decode_line(line.as_bytes(), MAX).unwrap();
        assert_eq!(back, m, "{line}");
    }
    let v: Value = serde_json::from_str(&encode(&Message::Error {
        id: None,
        error: RpcError::parse_error(),
    }))
    .unwrap();
    assert_eq!(v["id"], Value::Null);
    assert_eq!(v["jsonrpc"], "2.0");
}

#[test]
fn batch_is_invalid_request() {
    assert_eq!(
        code(r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#),
        INVALID_REQUEST
    );
    assert_eq!(code("[]"), INVALID_REQUEST);
    let e = decode_line(b"[1]", MAX).unwrap_err();
    assert_eq!(e.id, None);
}

#[test]
fn bad_json_is_parse_error_with_null_id() {
    for bad in [
        r#"{"jsonrpc":"2.0","id":1,"method":"ping""#,
        "{",
        "",
        "not json",
        r#"{"jsonrpc":"2.0","id":1,"method":"ping"} trailing"#,
        "\u{feff}{}",
    ] {
        let e = decode_line(bad.as_bytes(), MAX).unwrap_err();
        assert_eq!(e.error.code, PARSE_ERROR, "{bad:?}");
        assert_eq!(e.id, None, "{bad:?}");
        let reply = e.into_message();
        let v: Value = serde_json::from_str(&encode(&reply)).unwrap();
        assert_eq!(v["id"], Value::Null);
        assert_eq!(v["error"]["code"], PARSE_ERROR);
    }
    assert_eq!(
        decode_line(b"\xff\xfe{}", MAX).unwrap_err().error.code,
        PARSE_ERROR
    );
}

#[test]
fn null_id_rejected() {
    assert_eq!(
        code(r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#),
        INVALID_REQUEST
    );
    assert_eq!(
        code(r#"{"jsonrpc":"2.0","id":null,"result":{}}"#),
        INVALID_REQUEST
    );
    // A null id is valid only on an error response the server could not
    // attribute (a parse error).
    let m = decode_line(
        br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"x"}}"#,
        MAX,
    )
    .unwrap();
    assert!(matches!(m, Message::Error { id: None, .. }));
    // Other id shapes are invalid too.
    for id in ["true", "1.5", "{}", "[]", "-1e3"] {
        let line = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#);
        assert_eq!(code(&line), INVALID_REQUEST, "{line}");
    }
}

#[test]
fn string_and_number_ids_kept_exact() {
    for (raw, want) in [
        ("0", Id::Number(0.into())),
        ("-5", Id::Number((-5).into())),
        ("18446744073709551615", Id::Number(u64::MAX.into())),
        ("-9223372036854775808", Id::Number(i64::MIN.into())),
        (r#""""#, Id::String(String::new())),
        (r#""1""#, Id::String("1".into())),
        (r#"" a\u00e9\n""#, Id::String(" a\u{e9}\n".into())),
    ] {
        let line = format!(r#"{{"jsonrpc":"2.0","id":{raw},"method":"ping"}}"#);
        let m = decode_line(line.as_bytes(), MAX).unwrap();
        let Message::Request { id, .. } = &m else {
            panic!("{m:?}")
        };
        assert_eq!(id, &want, "{raw}");
        // The id goes back out as it came in: "1" stays a string, 1 a number.
        let out: Value = serde_json::from_str(&encode(&Message::Response {
            id: id.clone(),
            result: json!({}),
        }))
        .unwrap();
        let in_v: Value = serde_json::from_str(raw).unwrap();
        assert_eq!(out["id"], in_v, "{raw}");
    }
    // An id that does not fit u64/i64 is refused, not rounded.
    assert_eq!(
        code(r#"{"jsonrpc":"2.0","id":18446744073709551616,"method":"ping"}"#),
        INVALID_REQUEST
    );
}

#[test]
fn line_over_cap_reported_and_skipped() {
    let big = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"ping","params":{{"p":"{}"}}}}"#,
        "x".repeat(300)
    );
    let input = format!("{big}\n{}\n", r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#);
    // A tiny buffer so the over-cap line spans many fill_buf calls.
    let r = std::io::BufReader::with_capacity(16, Cursor::new(input.into_bytes()));
    let mut lr = LineReader::new(r, 100);
    let first = lr.next_message().unwrap().unwrap().unwrap_err();
    assert_eq!(first.error.code, INVALID_REQUEST);
    assert_eq!(first.id, None);
    let second = lr.next_message().unwrap().unwrap().unwrap();
    assert_eq!(
        second,
        Message::Request {
            id: Id::Number(2.into()),
            method: "ping".into(),
            params: None
        }
    );
    assert!(lr.next_message().unwrap().is_none());

    // decode_line applies the same cap.
    assert_eq!(
        decode_line(big.as_bytes(), 100).unwrap_err().error.code,
        INVALID_REQUEST
    );
    // A line of exactly the cap is fine; one byte more is not.
    let ok = r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#;
    assert!(decode_line(ok.as_bytes(), ok.len()).is_ok());
    assert!(decode_line(ok.as_bytes(), ok.len() - 1).is_err());
}

#[test]
fn line_reader_handles_crlf_blank_lines_and_eof_without_newline() {
    let input =
        "\n\r\n{\"jsonrpc\":\"2.0\",\"method\":\"a\"}\r\n{\"jsonrpc\":\"2.0\",\"method\":\"b\"}";
    let mut lr = LineReader::new(Cursor::new(input.as_bytes().to_vec()), 1000);
    for want in ["a", "b"] {
        match lr.next_message().unwrap().unwrap().unwrap() {
            Message::Notification { method, .. } => assert_eq!(method, want),
            m => panic!("{m:?}"),
        }
    }
    assert!(lr.next_message().unwrap().is_none());
    // An over-cap final line with no newline is still reported once.
    let mut lr = LineReader::new(Cursor::new(vec![b'x'; 50]), 10);
    assert_eq!(
        lr.next_message().unwrap().unwrap().unwrap_err().error.code,
        INVALID_REQUEST
    );
    assert!(lr.next_message().unwrap().is_none());
}

#[test]
fn encode_escapes_newlines() {
    let m = Message::Response {
        id: Id::String("a\nb\r".into()),
        result: json!({"text": "line1\nline2\r\n\u{2028}\u{0}", "k\n": 1}),
    };
    let line = encode(&m);
    assert_eq!(line.matches('\n').count(), 1);
    assert!(line.ends_with('\n'));
    assert!(!line.contains('\r'));
    assert_eq!(decode_line(line.trim_end().as_bytes(), MAX).unwrap(), m);
}

#[test]
fn version_and_bad_shapes_are_invalid_request() {
    for line in [
        r#"{"id":1,"method":"ping"}"#,
        r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#,
        r#"{"jsonrpc":2.0,"id":1,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":5}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":5}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":null}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"ping","result":1}"#,
        r#"{"jsonrpc":"2.0","id":1}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":1,"error":{"code":1,"message":"x"}}"#,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":"x","message":"x"}}"#,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":1.5,"message":"x"}}"#,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":1}}"#,
        r#"{"jsonrpc":"2.0","id":1,"error":5}"#,
        r#"{"jsonrpc":"2.0","method":"ping","result":null}"#,
        "5",
        "null",
        r#""str""#,
    ] {
        assert_eq!(code(line), INVALID_REQUEST, "{line}");
    }
    // The id is reported when it could be read, so the reply can name it.
    let e = decode_line(br#"{"jsonrpc":"1.0","id":"q","method":"ping"}"#, MAX).unwrap_err();
    assert_eq!(e.id, Some(Id::String("q".into())));
}

#[test]
fn duplicate_keys_are_refused_anywhere() {
    for line in [
        r#"{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call"}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"x","params":{"a":1,"a":2}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"x","params":{"a":[{"b":1,"b":1}]}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"x","params":{"a":1,"\u0061":2}}"#,
    ] {
        assert_eq!(code(line), PARSE_ERROR, "{line}");
    }
}

#[test]
fn nesting_is_bounded() {
    const { assert!(MAX_DEPTH < 64) };
    let nest = |depth: usize| {
        // The envelope is depth 1, params depth 2.
        let inner = depth - 2;
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"x","params":{{"a":{}0{}}}}}"#,
            "[".repeat(inner),
            "]".repeat(inner)
        )
    };
    assert!(decode_line(nest(MAX_DEPTH).as_bytes(), MAX).is_ok());
    assert_eq!(code(&nest(MAX_DEPTH + 1)), PARSE_ERROR);
    // Far past serde_json's own limit, on a small stack: no overflow.
    let deep = format!("{}{}", "[".repeat(500_000), "]".repeat(500_000));
    let deep_obj = "{\"a\":".repeat(200_000);
    let h = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || {
            let a = decode_line(deep.as_bytes(), usize::MAX)
                .unwrap_err()
                .error
                .code;
            let b = decode_line(deep_obj.as_bytes(), usize::MAX)
                .unwrap_err()
                .error
                .code;
            (a, b)
        })
        .unwrap();
    assert_eq!(h.join().unwrap(), (PARSE_ERROR, PARSE_ERROR));
}

#[test]
fn standard_codes() {
    assert_eq!(PARSE_ERROR, -32700);
    assert_eq!(INVALID_REQUEST, -32600);
    assert_eq!(METHOD_NOT_FOUND, -32601);
    assert_eq!(INVALID_PARAMS, -32602);
    assert_eq!(INTERNAL_ERROR, -32603);
    assert_eq!(RpcError::parse_error().code, PARSE_ERROR);
    assert_eq!(RpcError::invalid_request("x").code, INVALID_REQUEST);
    assert_eq!(RpcError::method_not_found("x").code, METHOD_NOT_FOUND);
    assert_eq!(RpcError::invalid_params("x").code, INVALID_PARAMS);
    assert_eq!(RpcError::internal_error("x").code, INTERNAL_ERROR);
}

#[test]
fn negotiate_table() {
    assert_eq!(PREFERRED, "2025-11-25");
    assert_eq!(SUPPORTED, ["2025-11-25", "2025-06-18"]);
    for (asked, want) in [
        ("2025-11-25", "2025-11-25"),
        ("2025-06-18", "2025-06-18"),
        ("2025-03-26", "2025-11-25"),
        ("2024-11-05", "2025-11-25"),
        ("2099-01-01", "2025-11-25"),
        ("", "2025-11-25"),
        ("2025-06-18 ", "2025-11-25"),
    ] {
        assert_eq!(negotiate(asked), want, "{asked:?}");
    }
}

#[test]
fn call_tool_result_serializes_camel_case() {
    let r = CallToolResult {
        content: vec![
            Content::Text { text: "hi".into() },
            Content::Resource {
                resource: ResourceContents {
                    uri: "saiife://response".into(),
                    mime_type: Some("application/octet-stream".into()),
                    text: None,
                    blob: Some("AAE=".into()),
                },
            },
        ],
        structured_content: Some(json!({"pending": 42})),
        is_error: true,
    };
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(
        v,
        json!({
            "content": [
                {"type": "text", "text": "hi"},
                {"type": "resource", "resource": {
                    "uri": "saiife://response",
                    "mimeType": "application/octet-stream",
                    "blob": "AAE="
                }}
            ],
            "structuredContent": {"pending": 42},
            "isError": true
        })
    );
    let back: CallToolResult = serde_json::from_value(v).unwrap();
    assert_eq!(back, r);
    // isError defaults to false when a server leaves it out.
    let r: CallToolResult = serde_json::from_value(json!({"content": []})).unwrap();
    assert!(!r.is_error);
    assert_eq!(r.structured_content, None);

    let t = Tool {
        name: "shopify_orders_list".into(),
        title: None,
        description: Some("List orders. Policy: allowed.".into()),
        input_schema: json!({"type": "object"}),
        output_schema: None,
        annotations: Some(saiife_mcp::types::ToolAnnotations {
            read_only_hint: Some(true),
            ..Default::default()
        }),
    };
    let v = serde_json::to_value(&t).unwrap();
    assert_eq!(
        v,
        json!({
            "name": "shopify_orders_list",
            "description": "List orders. Policy: allowed.",
            "inputSchema": {"type": "object"},
            "annotations": {"readOnlyHint": true}
        })
    );
}

#[test]
fn call_tool_params_read_progress_token() {
    let p: CallToolParams = serde_json::from_value(json!({
        "name": "linear__create_issue",
        "arguments": {"title": "x"},
        "_meta": {"progressToken": "tok-1"}
    }))
    .unwrap();
    assert_eq!(p.name, "linear__create_issue");
    assert_eq!(p.arguments.as_ref().unwrap()["title"], "x");
    assert_eq!(
        p.meta.unwrap().progress_token,
        Some(Id::String("tok-1".into()))
    );
    let p: CallToolParams =
        serde_json::from_value(json!({"name": "a", "_meta": {"progressToken": 3}})).unwrap();
    assert_eq!(p.meta.unwrap().progress_token, Some(Id::Number(3.into())));
    let p: CallToolParams = serde_json::from_value(json!({"name": "a"})).unwrap();
    assert!(p.arguments.is_none() && p.meta.is_none());
    let v = serde_json::to_value(CallToolParams {
        name: "a".into(),
        arguments: None,
        meta: Some(saiife_mcp::types::RequestMeta {
            progress_token: Some(Id::Number(1.into())),
        }),
    })
    .unwrap();
    assert_eq!(v, json!({"name": "a", "_meta": {"progressToken": 1}}));
}

#[test]
fn initialize_types_camel_case() {
    use saiife_mcp::types::{
        Implementation, InitializeParams, InitializeResult, ServerCapabilities, ToolsCapability,
    };
    let p: InitializeParams = serde_json::from_value(json!({
        "protocolVersion": "2025-06-18",
        "capabilities": {"roots": {}},
        "clientInfo": {"name": "claude-code", "version": "2.0"}
    }))
    .unwrap();
    assert_eq!(p.protocol_version, "2025-06-18");
    assert_eq!(p.client_info.unwrap().name, "claude-code");
    let r = InitializeResult {
        protocol_version: negotiate(&p.protocol_version).into(),
        capabilities: ServerCapabilities {
            tools: Some(ToolsCapability { list_changed: true }),
        },
        server_info: Implementation {
            name: "saiife".into(),
            version: "0.2.0".into(),
            title: None,
        },
        instructions: None,
    };
    assert_eq!(
        serde_json::to_value(&r).unwrap(),
        json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {"listChanged": true}},
            "serverInfo": {"name": "saiife", "version": "0.2.0"}
        })
    );
}

/// Fuzz-style table: hostile inputs, each with the outcome it must have.
/// Every decode must return (never panic), and an error always carries one
/// of the five standard codes.
#[test]
fn fuzz_table_never_panics() {
    let long_str = format!(r#"{{"jsonrpc":"2.0","method":"{}"}}"#, "m".repeat(10_000));
    let table: Vec<(Vec<u8>, Option<i64>)> = vec![
        (b"{}".to_vec(), Some(INVALID_REQUEST)),
        (b"{\"jsonrpc\":\"2.0\"}".to_vec(), Some(INVALID_REQUEST)),
        (b"\0".to_vec(), Some(PARSE_ERROR)),
        (b" ".to_vec(), Some(PARSE_ERROR)),
        (b"{\"a\":}".to_vec(), Some(PARSE_ERROR)),
        (b"{\"a\" 1}".to_vec(), Some(PARSE_ERROR)),
        (b"{'a':1}".to_vec(), Some(PARSE_ERROR)),
        (b"{\"a\":1,}".to_vec(), Some(PARSE_ERROR)),
        (b"[1,]".to_vec(), Some(PARSE_ERROR)),
        (b"{\"a\":NaN}".to_vec(), Some(PARSE_ERROR)),
        (b"{\"a\":Infinity}".to_vec(), Some(PARSE_ERROR)),
        (b"{\"a\":1e999}".to_vec(), Some(PARSE_ERROR)),
        (b"{\"a\":-}".to_vec(), Some(PARSE_ERROR)),
        (b"{\"a\":01}".to_vec(), Some(PARSE_ERROR)),
        (b"{\"a\":\"\\ud800\"}".to_vec(), Some(PARSE_ERROR)),
        (b"{\"a\":\"\\x\"}".to_vec(), Some(PARSE_ERROR)),
        (b"{\"a\":\"\x01\"}".to_vec(), Some(PARSE_ERROR)),
        (b"{\"a\":\"\xc3\x28\"}".to_vec(), Some(PARSE_ERROR)),
        (b"{\"a\":\"\xed\xa0\x80\"}".to_vec(), Some(PARSE_ERROR)),
        (b"{\"a\":1}{\"a\":1}".to_vec(), Some(PARSE_ERROR)),
        (b"{\"a\":1}\n{\"a\":1}".to_vec(), Some(PARSE_ERROR)),
        (b"\"\\u0000\"".to_vec(), Some(INVALID_REQUEST)),
        (b"true".to_vec(), Some(INVALID_REQUEST)),
        (b"-0".to_vec(), Some(INVALID_REQUEST)),
        (b"1e308".to_vec(), Some(INVALID_REQUEST)),
        // serde_json reads `-0` as a float, so it is not an exact integer id.
        (
            b"{\"jsonrpc\":\"2.0\",\"id\":-0,\"method\":\"ping\"}".to_vec(),
            Some(INVALID_REQUEST),
        ),
        (
            b"{\"jsonrpc\":\"2.0\",\"id\":1e2,\"method\":\"ping\"}".to_vec(),
            Some(INVALID_REQUEST),
        ),
        (
            b"{\"jsonrpc\":\"2.0\",\"method\":\"\\u0000\"}".to_vec(),
            None,
        ),
        (
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"params\":[]}".to_vec(),
            None,
        ),
        (
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"extra\":1}".to_vec(),
            None,
        ),
        (
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"m\",\"data\":[1]}}"
                .to_vec(),
            None,
        ),
        (
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":99999999999999999999,\"message\":\"m\"}}"
                .to_vec(),
            Some(INVALID_REQUEST),
        ),
        (long_str.into_bytes(), None),
        ("{\"jsonrpc\":\"2.0\",\"method\":\"é\u{10FFFF}\"}".as_bytes().to_vec(), None),
    ];
    for (input, want) in &table {
        let got = decode_line(input, MAX);
        match want {
            None => assert!(got.is_ok(), "{:?}: {got:?}", String::from_utf8_lossy(input)),
            Some(c) => assert_eq!(
                got.as_ref().err().map(|e| e.error.code),
                Some(*c),
                "{:?}: {got:?}",
                String::from_utf8_lossy(input)
            ),
        }
    }

    // Mutations of valid messages: every truncation, and seeded byte flips,
    // insertions and deletions. Only "returns without panicking, with a
    // standard code" is asserted.
    let seeds: Vec<Vec<u8>> = vec![
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a__b","arguments":{"x":[1,2.5,"s",null,true,{"y":"\u00e9"}]},"_meta":{"progressToken":"t"}}}"#.to_vec(),
        br#"{"jsonrpc":"2.0","id":"z","result":{"content":[{"type":"text","text":"a\nb"}],"isError":false}}"#.to_vec(),
        br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}"#.to_vec(),
        br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3}}"#.to_vec(),
    ];
    let std_codes = [
        PARSE_ERROR,
        INVALID_REQUEST,
        METHOD_NOT_FOUND,
        INVALID_PARAMS,
        INTERNAL_ERROR,
    ];
    let check = |b: &[u8]| {
        let r = decode_line(b, 4096);
        if let Err(e) = &r {
            assert!(std_codes.contains(&e.error.code), "{e:?}");
        }
        // Whatever decodes must re-encode to one line that decodes the same.
        if let Ok(m) = r {
            let line = encode(&m);
            assert_eq!(line.matches('\n').count(), 1);
            assert_eq!(
                decode_line(line.trim_end().as_bytes(), usize::MAX).unwrap(),
                m
            );
        }
        // The line reader sees the same input, split on newlines, and never
        // panics either.
        let mut lr = LineReader::new(Cursor::new(b.to_vec()), 64);
        let mut n = 0;
        while let Ok(Some(_)) = lr.next_message() {
            n += 1;
            assert!(n <= b.len() + 1);
        }
    };
    let alphabet = b"{}[]\":,\\0123456789-+.eE nultrfasx\n\r\t\x00\xff\xc3";
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut rnd = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for seed in &seeds {
        for i in 0..=seed.len() {
            check(&seed[..i]);
        }
        for _ in 0..3000 {
            let mut b = seed.clone();
            for _ in 0..(1 + rnd() % 4) {
                let pos = (rnd() as usize) % (b.len() + 1);
                let byte = alphabet[(rnd() as usize) % alphabet.len()];
                match rnd() % 3 {
                    0 if pos < b.len() => b[pos] = byte,
                    1 if pos < b.len() => {
                        b.remove(pos);
                    }
                    _ => b.insert(pos, byte),
                }
            }
            check(&b);
        }
    }
}
