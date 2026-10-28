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

/// Refuses what no path or query may hold: not origin-form, non-ASCII,
/// control characters, a fragment.
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
    if raw.contains('#') {
        return Err(bad_path("fragment"));
    }
    Ok(())
}

/// Traversal checks on the path part (before `?`). Query values are left to
/// `params::validate`.
fn check_path(raw: &str) -> Result<(), BrokerError> {
    if raw.contains("//") {
        return Err(bad_path("empty segment (//)"));
    }
    if raw.contains("..") {
        return Err(bad_path("contains .."));
    }
    if raw.contains('\\') {
        return Err(bad_path("backslash"));
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
    check_path(path)?;
    let segs: Vec<&str> = path[1..].split('/').collect();
    if segs.contains(&".") {
        return Err(bad_path("contains a . segment"));
    }
    let unknown = || BrokerError::UnknownOperation(format!("{method} {path}"));

    // Candidates with their specificity per segment: 2 literal, 1 placeholder
    // with prefix/suffix, 0 bare placeholder. Compared from the left; two
    // equally specific matches are ambiguous.
    let mut cands: Vec<(Vec<u8>, &Operation, BTreeMap<String, String>)> = Vec::new();
    // A GraphQL operation is named-only: its fixed document is the body,
    // so a proxied request can never reach it.
    for op in m
        .operation
        .iter()
        .filter(|o| o.method == method && o.graphql.is_none())
    {
        let Ok(tpl) = template_segments(&op.path) else {
            continue;
        };
        if tpl.len() != segs.len() {
            continue;
        }
        let mut caps = BTreeMap::new();
        let mut spec = Vec::with_capacity(tpl.len());
        let mut hit = true;
        for (t, s) in tpl.iter().zip(&segs) {
            match t {
                Seg::Lit(l) if l == s => spec.push(2),
                Seg::Lit(_) => {
                    hit = false;
                    break;
                }
                Seg::Var {
                    prefix,
                    name,
                    suffix,
                } => {
                    let Some(mid) = s
                        .strip_prefix(prefix)
                        .and_then(|r| r.strip_suffix(suffix))
                        .filter(|r| !r.is_empty())
                    else {
                        hit = false;
                        break;
                    };
                    let v = decode(mid).map_err(|()| bad_path("path is not valid UTF-8"))?;
                    caps.insert((*name).to_string(), v);
                    // A placeholder with a fixed prefix or suffix is more
                    // specific than a bare one.
                    spec.push(u8::from(!prefix.is_empty() || !suffix.is_empty()));
                }
            }
        }
        if hit {
            cands.push((spec, op, caps));
        }
    }
    cands.sort_by(|a, b| b.0.cmp(&a.0));
    if cands.len() > 1 && cands[0].0 == cands[1].0 {
        return Err(unknown());
    }
    let (_, op, mut params) = cands.into_iter().next().ok_or_else(unknown)?;

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
