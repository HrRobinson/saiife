//! Operation resolution (spec §6.7.1 step 4): named operations, and proxy
//! paths matched segment-wise on the raw (still percent-encoded) path.

use crate::manifest::{template_segments, Manifest, Operation, Seg};
use crate::BrokerError;
use percent_encoding::percent_decode_str;
use std::collections::BTreeMap;

pub fn named<'m>(m: &'m Manifest, id: &str) -> Option<&'m Operation> {
    m.operation.iter().find(|o| o.id == id)
}

fn bad_path(why: &str) -> BrokerError {
    BrokerError::BadPath(why.to_string())
}

/// Refuses everything but a plain origin-form path and query.
fn check_raw(raw: &str) -> Result<(), BrokerError> {
    if !raw.starts_with('/') {
        return Err(bad_path("not an origin-form path"));
    }
    if !raw.is_ascii() {
        return Err(bad_path("non-ASCII byte (percent-encode it)"));
    }
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(bad_path("control character"));
    }
    if raw.contains("//") {
        return Err(bad_path("empty segment (//)"));
    }
    if raw.contains("..") {
        return Err(bad_path("contains .."));
    }
    if raw.contains(['\\', '#']) {
        return Err(bad_path("backslash or fragment"));
    }
    let lower = raw.to_ascii_lowercase();
    for enc in ["%2e", "%2f", "%5c", "%00"] {
        if lower.contains(enc) {
            return Err(BrokerError::BadPath(format!("contains {enc}")));
        }
    }
    Ok(())
}

fn decode(s: &str) -> Result<String, ()> {
    percent_decode_str(s)
        .decode_utf8()
        .map(|c| c.into_owned())
        .map_err(|_| ())
}

fn bad_value(name: &str, why: &str) -> BrokerError {
    BrokerError::BadValue {
        name: name.to_string(),
        reason: why.to_string(),
    }
}

/// Matches `method` and `raw_path_and_query` against the manifest's
/// templates. Exactly one operation must match. The returned parameters
/// (path captures and query pairs) are percent-decoded once and still need
/// `params::validate`.
pub fn proxy<'m>(
    m: &'m Manifest,
    method: &str,
    raw_path_and_query: &str,
) -> Result<(&'m Operation, BTreeMap<String, String>), BrokerError> {
    check_raw(raw_path_and_query)?;
    let (path, query) = match raw_path_and_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (raw_path_and_query, None),
    };
    let segs: Vec<&str> = path[1..].split('/').collect();
    if segs.contains(&".") {
        return Err(bad_path("contains a . segment"));
    }
    let unknown = || BrokerError::UnknownOperation(format!("{method} {path}"));

    let mut found: Option<(&Operation, BTreeMap<String, String>)> = None;
    for op in m.operation.iter().filter(|o| o.method == method) {
        let Ok(tpl) = template_segments(&op.path) else {
            continue;
        };
        if tpl.len() != segs.len() {
            continue;
        }
        let mut caps = BTreeMap::new();
        let mut hit = true;
        for (t, s) in tpl.iter().zip(&segs) {
            match t {
                Seg::Lit(l) if l == s => {}
                Seg::Lit(_) => {
                    hit = false;
                    break;
                }
                Seg::Var(name) => {
                    let v = decode(s).map_err(|()| bad_path("path is not valid UTF-8"))?;
                    caps.insert((*name).to_string(), v);
                }
            }
        }
        if hit {
            if found.is_some() {
                return Err(unknown());
            }
            found = Some((op, caps));
        }
    }
    let (op, mut params) = found.ok_or_else(unknown)?;

    for pair in query.unwrap_or("").split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let k = decode(&k.replace('+', " ")).map_err(|()| bad_value("query", "not UTF-8"))?;
        if k.is_empty() {
            return Err(bad_value("query", "empty parameter name"));
        }
        let v = decode(&v.replace('+', " ")).map_err(|()| bad_value(&k, "not UTF-8"))?;
        if params.insert(k.clone(), v).is_some() {
            return Err(bad_value(&k, "given twice"));
        }
    }
    Ok((op, params))
}
