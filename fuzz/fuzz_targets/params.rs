#![no_main]
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

// Byte 0 picks a built-in operation; the rest is lines `k=v`. Those before
// the first blank line are agent-given, those after it are policy-fixed.
fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    let Ok(s) = std::str::from_utf8(rest) else {
        return;
    };
    let ops: Vec<_> = saiife_broker::manifest::builtin()
        .iter()
        .flat_map(|m| m.operation.iter())
        .collect();
    if ops.is_empty() {
        return;
    }
    let op = ops[pick as usize % ops.len()];
    let mut given = BTreeMap::new();
    let mut fixed = BTreeMap::new();
    let mut in_fixed = false;
    for line in s.split('\n') {
        if line.is_empty() {
            in_fixed = true;
            continue;
        }
        let (k, v) = line.split_once('=').unwrap_or((line, ""));
        let map = if in_fixed { &mut fixed } else { &mut given };
        map.insert(k.to_string(), v.to_string());
    }
    let _ = saiife_broker::params::validate(op, &given, &fixed);
});
