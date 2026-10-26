#![no_main]
use libfuzzer_sys::fuzz_target;
use saiife_daemon::gateway::{classify, Target};

// Line 1: the method; the rest: the raw request target as received. The
// parsed Uri is built from the same text when it parses at all, as on the
// real path; otherwise the default URI stands in for it.
fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let (m, raw) = s.split_once('\n').unwrap_or(("GET", s));
    let Ok(method) = http::Method::from_bytes(m.as_bytes()) else {
        return;
    };
    let uri: http::Uri = raw.parse().unwrap_or_default();
    let req = http::Request::builder()
        .method(method)
        .uri(uri)
        .body(bytes::Bytes::new())
        .unwrap();
    let t = classify(req.method(), req.uri(), Some(raw));
    // Whatever is routed came as origin-form, without a fragment.
    if matches!(
        t,
        Target::Api { .. } | Target::Proxy { .. } | Target::Services | Target::Requests
    ) {
        assert!(raw.starts_with('/') && !raw.contains('#'));
    }
    assert!(matches!(
        classify(req.method(), req.uri(), None),
        Target::BadRequest(_)
    ));
});
