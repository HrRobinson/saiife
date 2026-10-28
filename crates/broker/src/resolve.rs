//! Operation resolution (spec §6.7.1 step 4): named operations, and proxy
//! paths matched segment-wise on the raw (still percent-encoded) path.

use crate::manifest::{template_segments, Manifest, Operation, Seg, OBJECT_KEY};
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
    // A mail operation is named-only: there is no path to send.
    if m.transport == crate::manifest::Transport::Mail {
        return Err(BrokerError::UnknownOperation(
            "a proxy path (mail operations are named only)".into(),
        ));
    }
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
    // equally specific matches are ambiguous. Equally specific paths are
    // then told apart by their fixed query (S3's `GET /{key}?acl` next to
    // GetObject): first an op whose fixed names the query all carries, then
    // the one with the most of them.
    let query_names: std::collections::BTreeSet<String> = query
        .unwrap_or("")
        .split('&')
        .filter_map(|p| decode(&p.split('=').next()?.replace('+', " ")).ok())
        .collect();
    type Rank = (Vec<u8>, bool, usize);
    let mut cands: Vec<(Rank, &Operation, BTreeMap<String, String>)> = Vec::new();
    // A GraphQL operation is named-only: its fixed document is the body,
    // so a proxied request can never reach it. So is one with an
    // `objectname`, whose `/` is `%2F`, which no raw path may hold.
    for op in m
        .operation
        .iter()
        .filter(|o| o.method == method && o.proxy_reachable())
    {
        let Ok(tpl) = template_segments(&op.path) else {
            continue;
        };
        // An `objectkey` last segment takes the rest of the path (one or
        // more segments; `check_path` refused `//`, `..` and encoded
        // separators already).
        let tail = match tpl.last() {
            Some(Seg::Var {
                prefix: "",
                name,
                suffix: "",
            }) if op.path_params.get(*name).map(String::as_str) == Some(OBJECT_KEY) => Some(*name),
            _ => None,
        };
        let fixed = if tail.is_some() {
            tpl.len() - 1
        } else {
            tpl.len()
        };
        if segs.len() < tpl.len() || (tail.is_none() && segs.len() != tpl.len()) {
            continue;
        }
        let mut caps = BTreeMap::new();
        let mut spec = Vec::with_capacity(tpl.len());
        let mut hit = true;
        if let Some(name) = tail {
            let rest = &segs[fixed..];
            if rest.iter().any(|s| s.is_empty()) {
                continue;
            }
            let v = decode(&rest.join("/")).map_err(|()| bad_path("path is not valid UTF-8"))?;
            caps.insert(name.to_string(), v);
        }
        for (t, s) in tpl[..fixed].iter().zip(&segs) {
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
            // The tail counts as a bare placeholder.
            if tail.is_some() {
                spec.push(0);
            }
            let present = op
                .fixed_query
                .keys()
                .filter(|k| query_names.contains(*k))
                .count();
            let rank = (spec, present == op.fixed_query.len(), present);
            cands.push((rank, op, caps));
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
    // A fixed query value may be repeated exactly, never changed; the
    // request builder appends it.
    for (k, fixed) in &op.fixed_query {
        if let Some(v) = params.remove(k) {
            if &v != fixed {
                return Err(BrokerError::BadPath(format!(
                    "query parameter {k} is fixed by the connector"
                )));
            }
        }
    }
    Ok((op, params))
}
