//! R-T3o: the comparison key is a full case fold. Every char in
//! U+0000..=U+1FFFF keys like its full (multi-char) uppercase and its full
//! lowercase, so no NFC spelling a case-insensitive host treats as the same
//! name keys apart.

use saiife_boxproto::delta::normalize_component;

#[test]
fn every_char_keys_like_its_upper_and_lower_case() {
    let mut bad = Vec::new();
    let mut seen = 0u32;
    for cp in 0..=0x1FFFFu32 {
        // Surrogates are not chars.
        let Some(c) = char::from_u32(cp) else {
            continue;
        };
        seen += 1;
        let s = c.to_string();
        let up: String = c.to_uppercase().collect();
        let low: String = c.to_lowercase().collect();
        let k = normalize_component(&s);
        if normalize_component(&up) != k || normalize_component(&low) != k {
            bad.push(format!("U+{cp:04X}"));
        }
    }
    assert_eq!(seen, 0x20000 - 0x800);
    assert!(bad.is_empty(), "{} chars key apart: {bad:?}", bad.len());
}
