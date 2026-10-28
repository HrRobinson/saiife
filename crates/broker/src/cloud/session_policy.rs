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
//! - An operation's qualifier is taken as the IAM resource ARN only when
//!   every `{placeholder}` in it is one of its path params (always
//!   required). A qualifier built from a query param (`{prefix}` of a
//!   `ListBucket`) or a service param names something IAM does not see, so
//!   a qualified allow matching such an operation is refused and a deny on
//!   it denies `*`.
//! - An allow that grants an IAM action must allow every operation with
//!   that action; an action shared with an operation it does not allow
//!   (another verb, or unqualified under a qualified allow) is refused.
//! - The project overlay counts as in `saiife_policy::decide`: its `ask`
//!   and `deny` always, its `allow` only in developer mode.
//! - `ask` and `deny` patterns and rules (their `when` ignored) give
//!   `Deny <iam_action>`. Saiife matches them broadly (a `*` crosses `/`,
//!   ASCII case is ignored, a qualified pattern matches an unqualified
//!   request), so the IAM resource is made at least as wide: the ARN header
//!   is lower-cased (AWS writes it in lower case), every letter after it,
//!   and every `?`, `$`, `{` or `}`, becomes IAM's single-character `?`,
//!   and everything from the first `*` or non-ASCII character on becomes a
//!   trailing `*`. A qualifier that is not such an ARN denies `*`. The
//!   deny is therefore often wider than the saiife one, never narrower.
//! - The output is deterministic JSON of at most [`MAX_POLICY`] bytes.

use std::collections::{BTreeMap, BTreeSet};

use saiife_policy::{Action, Capability, Mode, ServiceCfg, ServiceOverlay};
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

/// An operation a pattern's resource and verb match.
struct Matched<'m> {
    op: &'m Operation,
    /// The operation has a qualifier.
    qualified: bool,
    /// Its qualifier is the IAM resource ARN: every placeholder in it is a
    /// path param of the operation.
    arn: bool,
}

/// Every `{name}` in `t` is a path param of `op`.
fn placeholders_are_path_params(t: &str, op: &Operation) -> bool {
    let mut rest = t;
    while let Some(k) = rest.find('{') {
        if rest[..k].contains('}') {
            return false;
        }
        let Some(e) = rest[k..].find('}') else {
            return false;
        };
        if !op.path_params.contains_key(&rest[k + 1..k + e]) {
            return false;
        }
        rest = &rest[k + e + 1..];
    }
    !rest.contains('}')
}

/// The operations whose capability the pattern's resource and verb match.
fn matching<'m>(m: &'m Manifest, res: &str, verb: &str) -> Vec<Matched<'m>> {
    m.operation
        .iter()
        .filter_map(|op| {
            let cap = Capability::parse(&op.capability).ok()?;
            let ok = (res == "*" || res == cap.resource) && (verb == "*" || verb == cap.verb);
            if !ok {
                return None;
            }
            let template = op.qualifier.as_deref().or(cap.qualifier.as_deref());
            Some(Matched {
                op,
                qualified: template.is_some(),
                arn: template.is_some_and(|t| placeholders_are_path_params(t, op)),
            })
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
    // Cut at the first `*` (saiife's broad `*` crosses `:`, IAM's does not
    // in mid-pattern) or non-ASCII character (its case folding and IAM
    // reading are not worth guessing), and match any rest.
    let (prefix, star) = match q.find(|c: char| c == '*' || !c.is_ascii()) {
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
    let mut allowed: Vec<&str> = Vec::new();
    let mut actions: BTreeSet<&str> = BTreeSet::new();
    for x in matching(m, res, verb) {
        // Saiife's allow stage: a qualified pattern does not match an
        // unqualified request.
        if qual.is_some() && !x.qualified {
            continue;
        }
        if qual.is_some() && !x.arn {
            return Err(unrep(
                p,
                "it allows an operation whose qualifier is not its IAM resource ARN (a placeholder is not a path param)",
            ));
        }
        let a =
            x.op.iam_action
                .as_deref()
                .ok_or_else(|| unrep(p, "it allows an operation without an iam_action"))?;
        if a.contains('*') {
            return Err(unrep(
                p,
                "it allows an operation whose iam_action holds `*`",
            ));
        }
        allowed.push(&x.op.id);
        actions.insert(a);
    }
    // A granted action must not also reach an operation this pattern does
    // not allow (another verb, or unqualified under a qualified pattern).
    for op in &m.operation {
        let shared = op
            .iam_action
            .as_deref()
            .is_some_and(|a| actions.contains(a));
        if shared && !allowed.contains(&op.id.as_str()) {
            return Err(unrep(
                p,
                "an IAM action it grants is shared with an operation it does not allow",
            ));
        }
    }
    for a in actions {
        g.entry(resource.clone()).or_default().insert(a.to_string());
    }
    Ok(())
}

fn add_deny(p: &str, m: &Manifest, g: &mut Grants) -> Result<(), CloudError> {
    let (res, verb, qual) = split(p).ok_or_else(|| unrep(p, "not a valid pattern"))?;
    for x in matching(m, res, verb) {
        let Some(a) = x.op.iam_action.as_deref() else {
            continue;
        };
        // Broad: a qualified deny matches an unqualified request, and one
        // whose qualifier is not the IAM ARN cannot be narrowed.
        let resource = match qual {
            Some(q) if x.qualified && x.arn => deny_resource(q),
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

/// The session policy of `svc` on `m` (decision 10), with the project
/// `overlay` counted as `saiife_policy::decide` counts it in `mode`.
pub fn build(
    svc: &ServiceCfg,
    m: &Manifest,
    overlay: Option<&ServiceOverlay>,
    mode: Mode,
) -> Result<SessionPolicy, CloudError> {
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
    let o_allow: &[String] = match (overlay, mode) {
        (Some(o), Mode::Developer) => &o.allow,
        _ => &[],
    };
    let (o_ask, o_deny): (&[String], &[String]) = match overlay {
        Some(o) => (&o.ask, &o.deny),
        None => (&[], &[]),
    };
    for p in svc.allow.iter().chain(o_allow) {
        add_allow(p, m, &mut allow)?;
    }
    for p in svc.ask.iter().chain(&svc.deny).chain(o_ask).chain(o_deny) {
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
        // Non-ASCII: cut there and match any rest.
        assert_eq!(
            deny_resource("arn:aws:s3:::b/r\u{e9}sum\u{e9}/x"),
            "arn:aws:s3:::?/?*"
        );
        assert_eq!(deny_resource("arn:aws:s3:::\u{e9}"), "arn:aws:s3:::*");
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
