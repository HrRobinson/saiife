#![no_main]
use libfuzzer_sys::fuzz_target;

// First line: the method; the rest: the raw path and query.
fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let (method, path) = s.split_once('\n').unwrap_or(("GET", s));
    for m in saiife_broker::manifest::builtin() {
        let _ = saiife_broker::resolve::proxy(m, method, path);
    }
});
