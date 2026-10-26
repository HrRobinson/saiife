#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = saiife_ipc::frame::decode(data);
    if let Some(h) = data.get(..4) {
        let header = [h[0], h[1], h[2], h[3]];
        if let Ok(n) = saiife_ipc::frame::body_len(header) {
            assert!(n > 0);
        }
    }
});
