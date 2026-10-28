//! The inline STS session policy of `mode = "sts"` (decision 10). It never
//! widens the saiife policy: every AWS request it allows is one the saiife
//! policy of the service allows too.
//!
//! - An `allow` pattern (or an `allow` rule without `when`) gives
//!   `Allow <iam_action>` for each operation it matches. A pattern without a
//!   qualifier gives `Resource "*"`; a qualifier must be an ARN whose header
//!   (`arn:partition:service:region:account:`) is lower case, and it is
//!   copied as is, with a trailing `**` becoming IAM's `*` (both match any
//!   rest). Anything IAM reads differently is refused as
//!   [`CloudError::Unrepresentable`]: a single `*` (it stays within one `/`
//!   level in saiife and crosses `/` in IAM), a `**` that is not trailing,
//!   `?` (an IAM wildcard), `$`, `{` and `}` (IAM policy variables), and
//!   bytes outside printable ASCII. An allow rule with `when`, an `allow`
//!   matching an operation without `iam_action`, an `iam_action` holding
//!   `*`, and a `fixed` parameter are refused too.
//! - `ask` and `deny` patterns and rules (their `when` ignored) give
//!   `Deny <iam_action>`. Saiife matches them broadly (a `*` crosses `/`,
//!   ASCII case is ignored, a qualified pattern matches an unqualified
//!   request), so the IAM resource is made at least as wide: the ARN header
//!   is lower-cased (AWS writes it in lower case), every letter after it,
//!   and every `?`, `$`, `{`, `}` or non-ASCII character, becomes IAM's
//!   single-character `?`, and everything after the first `*` becomes a
//!   trailing `*`. A qualifier that is not such an ARN denies `*`. The
//!   deny is therefore often wider than the saiife one, never narrower.
//! - The output is deterministic JSON of at most [`MAX_POLICY`] bytes.

use std::collections::{BTreeMap, BTreeSet};

use saiife_policy::{Action, Capability, ServiceCfg};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::CloudError;
use crate::manifest::{Manifest, Operation};

/// The AWS limit on an inline session policy, in characters (all ASCII).
pub const MAX_POLICY: usize = 2048;

/// The policy text sent as `Policy` and its SHA-256 (hex) for the lease
/// record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPolicy {
    pub json: String,
    pub sha256: String,
}

#[derive(Serialize)]
struct Doc {
    #[serde(rename = "Version")]
    version: &'static str,
    #[serde(rename = "Statement")]
    statement: Vec<Stmt>,
}

#[derive(Serialize)]
struct Stmt {
    #[serde(rename = "Effect")]
    effect: &'static str,
    #[serde(rename = "Action")]
    action: Vec<String>,
    #[serde(rename = "Resource")]
    resource: Vec<String>,
}

/// Resource → IAM actions.
type Grants = BTreeMap<String, BTreeSet<String>>;

fn unrep(pattern: &str, why: &'static str) -> CloudError {
    CloudError::Unrepresentable {
        pattern: pattern.to_string(),
        why,
    }
}

/// `resource:verb[:qualifier]`.
fn split(p: &str) -> Option<(&str, &str, Option<&str>)> {
    saiife_policy::capability::validate_pattern(p).ok()?;
    let mut it = p.splitn(3, ':');
    Some((it.next()?, it.next()?, it.next()))
}

/// The operations whose capability the pattern's resource and verb match,
/// each with whether it has a qualifier.
fn matching<'m>(m: &'m Manifest, res: &str, verb: &str) -> Vec<(&'m Operation, bool)> {
    m.operation
        .iter()
        .filter_map(|op| {
            let cap = Capability::parse(&op.capability).ok()?;
            let ok = (res == "*" || res == cap.resource) && (verb == "*" || verb == cap.verb);
            ok.then_some((op, op.qualifier.is_some() || cap.qualifier.is_some()))
        })
        .collect()
}

/// The length of a lower-case ARN header `arn:p:s:r:a:` at the start of
/// `q` (each part `[a-z0-9-]*`, the partition and service not empty).
fn arn_header(q: &str) -> Option<usize> {
    let rest = q.strip_prefix("arn:")?;
    let mut at = 4;
    let mut parts = rest.splitn(5, ':');
    for i in 0..4 {
        let part = parts.next()?;
        parts.clone().next()?; // a colon follows
        if (i < 2 && part.is_empty())
            || !part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return None;
        }
        at += part.len() + 1;
    }
    Some(at)
}

/// The IAM resource of an allow qualifier, exactly as wide.
fn allow_resource(q: &str) -> Result<String, &'static str> {
    let (body, star) = match q.strip_suffix("**") {
        Some(b) => (b, true),
        None => (q, false),
    };
    let h = arn_header(body).ok_or(
        "the qualifier must start with an ARN header in lower case (arn:partition:service:region:account:)",
    )?;
    for c in body[h..].chars() {
        match c {
            '*' => {
                return Err("a `*` other than a trailing `**` is read differently by IAM (saiife's single `*` stays within one `/` level)")
            }
            '?' => return Err("`?` is an IAM wildcard"),
            '$' | '{' | '}' => return Err("`$`, `{` and `}` are IAM policy-variable syntax"),
            c if !(' '..='~').contains(&c) => {
                return Err("only printable ASCII can be expressed in a session policy")
            }
            _ => {}
        }
    }
    Ok(if star {
        format!("{body}*")
    } else {
        body.to_string()
    })
}

/// The IAM resource of a deny or ask qualifier: at least as wide as
/// saiife's broad, case-insensitive match.
fn deny_resource(q: &str) -> String {
    let (prefix, star) = match q.find('*') {
        Some(k) => (&q[..k], true),
        None => (q, false),
    };
    let lower = prefix.to_ascii_lowercase();
    let Some(h) = arn_header(&lower) else {
        return "*".to_string();
    };
    let mut out = lower[..h].to_string();
    for c in prefix[h..].chars() {
        let wild = c.is_ascii_alphabetic()
            || matches!(c, '?' | '$' | '{' | '}')
            || !(' '..='~').contains(&c);
        out.push(if wild { '?' } else { c });
    }
    if star {
        out.push('*');
    }
    out
}

fn add_allow(p: &str, m: &Manifest, g: &mut Grants) -> Result<(), CloudError> {
    let (res, verb, qual) = split(p).ok_or_else(|| unrep(p, "not a valid pattern"))?;
    let resource = match qual {
        None => "*".to_string(),
        Some(q) => allow_resource(q).map_err(|why| unrep(p, why))?,
    };
    for (op, qualified) in matching(m, res, verb) {
        // Saiife's allow stage: a qualified pattern does not match an
        // unqualified request.
        if qual.is_some() && !qualified {
            continue;
        }
        let a = op
            .iam_action
            .as_deref()
            .ok_or_else(|| unrep(p, "it allows an operation without an iam_action"))?;
        if a.contains('*') {
            return Err(unrep(
                p,
                "it allows an operation whose iam_action holds `*`",
            ));
        }
        g.entry(resource.clone()).or_default().insert(a.to_string());
    }
    Ok(())
}

fn add_deny(p: &str, m: &Manifest, g: &mut Grants) -> Result<(), CloudError> {
    let (res, verb, qual) = split(p).ok_or_else(|| unrep(p, "not a valid pattern"))?;
    for (op, qualified) in matching(m, res, verb) {
        let Some(a) = op.iam_action.as_deref() else {
            continue;
        };
        // Broad: a qualified deny matches an unqualified request.
        let resource = match qual {
            Some(q) if qualified => deny_resource(q),
            _ => "*".to_string(),
        };
        g.entry(resource).or_default().insert(a.to_string());
    }
    Ok(())
}

/// Groups resources with the same action set into one statement.
fn statements(effect: &'static str, g: Grants) -> Vec<Stmt> {
    let mut by_actions: BTreeMap<Vec<String>, Vec<String>> = BTreeMap::new();
    for (res, acts) in g {
        by_actions
            .entry(acts.into_iter().collect())
            .or_default()
            .push(res);
    }
    by_actions
        .into_iter()
        .map(|(action, resource)| Stmt {
            effect,
            action,
            resource,
        })
        .collect()
}

/// The session policy of `svc` on `m` (decision 10).
pub fn build(svc: &ServiceCfg, m: &Manifest) -> Result<SessionPolicy, CloudError> {
    if !m.signs_sigv4() {
        return Err(unrep(
            &m.id,
            "STS mode is for AWS (aws_sigv4) connectors only",
        ));
    }
    if let Some(k) = svc.fixed.keys().next() {
        return Err(unrep(
            &format!("fixed.{k}"),
            "a fixed parameter cannot be expressed in a session policy",
        ));
    }
    let mut allow = Grants::new();
    let mut deny = Grants::new();
    for p in &svc.allow {
        add_allow(p, m, &mut allow)?;
    }
    for p in svc.ask.iter().chain(&svc.deny) {
        add_deny(p, m, &mut deny)?;
    }
    for r in &svc.rule {
        match r.action {
            Action::Allow if !r.when.is_empty() => {
                return Err(unrep(
                    &r.capability,
                    "an allow rule with `when` cannot be expressed in a session policy",
                ))
            }
            Action::Allow => add_allow(&r.capability, m, &mut allow)?,
            Action::Ask | Action::Deny => add_deny(&r.capability, m, &mut deny)?,
        }
    }
    if allow.is_empty() {
        return Err(unrep(
            &m.id,
            "the policy allows no operation of this service",
        ));
    }
    let mut statement = statements("Allow", allow);
    statement.extend(statements("Deny", deny));
    let json = serde_json::to_string(&Doc {
        version: "2012-10-17",
        statement,
    })
    .map_err(|_| CloudError::Response("the session policy does not serialize".into()))?;
    if json.len() > MAX_POLICY {
        return Err(CloudError::TooLarge);
    }
    let sha256 = Sha256::digest(json.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(SessionPolicy { json, sha256 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers() {
        assert_eq!(arn_header("arn:aws:s3:::b/k"), Some(13));
        assert_eq!(
            arn_header("arn:aws:dynamodb:us-east-1:123456789012:table/t"),
            Some(40)
        );
        assert_eq!(arn_header("arn:aws:s3::"), None);
        assert_eq!(arn_header("ARN:aws:s3:::b"), None);
        assert_eq!(arn_header("arn::s3:::b"), None);
        assert_eq!(arn_header("arn:aws:s*:::b"), None);
    }

    #[test]
    fn deny_widening() {
        assert_eq!(
            deny_resource("arn:aws:s3:::b1/Se-cret/*"),
            "arn:aws:s3:::?1/??-????/*"
        );
        assert_eq!(deny_resource("ARN:AWS:S3:::x"), "arn:aws:s3:::?");
        assert_eq!(deny_resource("arn:aws:s3:::r/*/x:y"), "arn:aws:s3:::?/*");
        assert_eq!(
            deny_resource("arn:aws:s3:::${aws:username}"),
            "arn:aws:s3:::?????:?????????"
        );
        assert_eq!(deny_resource("*secret*"), "*");
        assert_eq!(deny_resource("arn:aws:*"), "*");
    }
}
