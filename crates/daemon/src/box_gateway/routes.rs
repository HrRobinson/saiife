//! The model forwarder's route table (plan 42 D1, D4, ruling R12): per
//! provider, the one upstream host (port 443), the vault services a key
//! must allow and the exact (method, path, query) requests forwarded.
//! Pure: no I/O here; [`super::model`] is the only place that touches the
//! network.
//!
//! The box never picks its route: the forwarder takes it from the box's
//! template (`AgentKind::provider()`) on every request.

use http::header::{HeaderName, AUTHORIZATION};
use http::Method;
use saiife_boxes::template::{ModelCred, Provider};

/// One provider's route.
#[derive(Debug)]
pub struct Route {
    pub provider: Provider,
    /// The upstream host; the port is always 443.
    pub host: &'static str,
    /// The vault services a key for this route may allow (any one); the
    /// first is the one a refusal names.
    pub services: &'static [&'static str],
    /// The requests forwarded (R12); anything else is `path_not_allowed`.
    pub allow: &'static [Allow],
}

/// One allowed request shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allow {
    /// `"GET"` or `"POST"`.
    pub method: &'static str,
    pub path: PathRule,
    /// The only query keys allowed, each at most once.
    pub query: &'static [Param],
}

/// The raw origin-form path (no query).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRule {
    /// Exactly this path.
    Exact(&'static str),
    /// `prefix`, one [`is_id`] segment, then `suffix`.
    Id {
        prefix: &'static str,
        suffix: &'static str,
    },
}

/// One allowed query key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Param {
    pub name: &'static str,
    pub value: ValueRule,
    /// The key must be present.
    pub required: bool,
}

/// What a query value may be (as sent, never decoded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueRule {
    /// Exactly this text.
    Exact(&'static str),
    /// 1 to this many ASCII digits.
    Digits(usize),
    /// A client version: `[0-9A-Za-z.+-]{1,32}`.
    Version,
}

const fn opt(name: &'static str, value: ValueRule) -> Param {
    Param {
        name,
        value,
        required: false,
    }
}

const BETA: Param = opt("beta", ValueRule::Exact("true"));

pub const ANTHROPIC: Route = Route {
    provider: Provider::Anthropic,
    host: "api.anthropic.com",
    // TODO(release): drop the legacy "box-model" alias (owner decision OD4, plan 42 D6)
    services: &["box-model-anthropic", "box-model"],
    allow: &[
        Allow {
            method: "POST",
            path: PathRule::Exact("/v1/messages"),
            query: &[BETA],
        },
        Allow {
            method: "POST",
            path: PathRule::Exact("/v1/messages/count_tokens"),
            query: &[BETA],
        },
        Allow {
            method: "GET",
            path: PathRule::Exact("/v1/models"),
            query: &[BETA, opt("limit", ValueRule::Digits(4))],
        },
        Allow {
            method: "GET",
            path: PathRule::Id {
                prefix: "/v1/models/",
                suffix: "",
            },
            query: &[BETA],
        },
    ],
};

pub const OPENAI: Route = Route {
    provider: Provider::OpenAi,
    host: "api.openai.com",
    services: &["box-model-openai"],
    allow: &[
        Allow {
            method: "POST",
            path: PathRule::Exact("/v1/responses"),
            query: &[],
        },
        Allow {
            method: "GET",
            path: PathRule::Exact("/v1/models"),
            query: &[opt("client_version", ValueRule::Version)],
        },
        Allow {
            method: "GET",
            path: PathRule::Id {
                prefix: "/v1/models/",
                suffix: "",
            },
            query: &[],
        },
    ],
};

pub const GOOGLE: Route = Route {
    provider: Provider::Google,
    host: "generativelanguage.googleapis.com",
    services: &["box-model-google"],
    allow: &[
        Allow {
            method: "POST",
            path: PathRule::Id {
                prefix: "/v1beta/models/",
                suffix: ":streamGenerateContent",
            },
            query: &[Param {
                name: "alt",
                value: ValueRule::Exact("sse"),
                required: true,
            }],
        },
        Allow {
            method: "POST",
            path: PathRule::Id {
                prefix: "/v1beta/models/",
                suffix: ":generateContent",
            },
            query: &[],
        },
        Allow {
            method: "POST",
            path: PathRule::Id {
                prefix: "/v1beta/models/",
                suffix: ":countTokens",
            },
            query: &[],
        },
    ],
};

/// The route of `provider` (D1).
pub fn route(provider: Provider) -> &'static Route {
    match provider {
        Provider::Anthropic => &ANTHROPIC,
        Provider::OpenAi => &OPENAI,
        Provider::Google => &GOOGLE,
    }
}

/// The provider whose key `cred` stands in for.
pub fn provider_of(cred: ModelCred) -> Provider {
    match cred {
        ModelCred::AnthropicApiKey | ModelCred::AnthropicSubscription => Provider::Anthropic,
        ModelCred::OpenAiApiKey => Provider::OpenAi,
        ModelCred::GoogleApiKey => Provider::Google,
    }
}

/// The one header that carries `cred`, and whether its value is
/// `Bearer <key>` (D1).
pub fn cred_header(cred: ModelCred) -> (HeaderName, bool) {
    match cred {
        ModelCred::AnthropicApiKey => (HeaderName::from_static("x-api-key"), false),
        ModelCred::AnthropicSubscription | ModelCred::OpenAiApiKey => (AUTHORIZATION, true),
        ModelCred::GoogleApiKey => (HeaderName::from_static("x-goog-api-key"), false),
    }
}

/// Percent-encodings that are never plain: `.`, `/`, `\` and NUL.
const ENCODED_TRICKS: [&[u8]; 4] = [b"%2e", b"%2f", b"%5c", b"%00"];

/// Whether the raw origin-form path (no query) is plain (D4): only visible
/// ASCII, no `\`, no percent-encoded `.`, `/`, `\` or NUL (any case), and
/// no empty, `.` or `..` segment (so no `//` and no trailing `/`).
pub fn path_plain(raw_path: &str) -> bool {
    let b = raw_path.as_bytes();
    let Some(rest) = raw_path.strip_prefix('/') else {
        return false;
    };
    if !b.iter().all(|c| (0x21..=0x7e).contains(c)) || b.contains(&b'\\') {
        return false;
    }
    let lower = raw_path.to_ascii_lowercase();
    if ENCODED_TRICKS
        .iter()
        .any(|t| lower.as_bytes().windows(t.len()).any(|w| w == *t))
    {
        return false;
    }
    rest.split('/').all(|seg| !matches!(seg, "" | "." | ".."))
}

/// A model ID segment (R12): `[A-Za-z0-9._-]{1,128}`, not `.` or `..`.
pub fn is_id(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

impl PathRule {
    fn matches(&self, raw_path: &str) -> bool {
        match *self {
            PathRule::Exact(p) => raw_path == p,
            PathRule::Id { prefix, suffix } => raw_path
                .strip_prefix(prefix)
                .and_then(|r| r.strip_suffix(suffix))
                .is_some_and(is_id),
        }
    }
}

impl ValueRule {
    fn matches(&self, v: &str) -> bool {
        match *self {
            ValueRule::Exact(want) => v == want,
            ValueRule::Digits(max) => {
                (1..=max).contains(&v.len()) && v.bytes().all(|c| c.is_ascii_digit())
            }
            ValueRule::Version => {
                (1..=32).contains(&v.len())
                    && v.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'+' | b'-'))
            }
        }
    }
}

/// Whether `raw_query` has only `params`' keys, each at most once as
/// `name=value` with its value rule, and every required one.
fn query_ok(params: &[Param], raw_query: Option<&str>) -> bool {
    let mut seen = [false; 8];
    debug_assert!(params.len() <= seen.len());
    if let Some(q) = raw_query {
        for piece in q.split('&') {
            let Some((name, value)) = piece.split_once('=') else {
                return false;
            };
            let Some(i) = params.iter().position(|p| p.name == name) else {
                return false;
            };
            if i >= seen.len() || seen[i] || !params[i].value.matches(value) {
                return false;
            }
            seen[i] = true;
        }
    }
    params
        .iter()
        .enumerate()
        .all(|(i, p)| !p.required || seen.get(i).copied().unwrap_or(false))
}

/// Whether the request is one of the route's allowed shapes (R12): the
/// path plain and matching, the method the shape's, and the query only the
/// shape's keys, each at most once, each value by its rule, the required
/// ones present.
pub fn allowed(route: &Route, method: &Method, raw_path: &str, raw_query: Option<&str>) -> bool {
    path_plain(raw_path)
        && route.allow.iter().any(|a| {
            method.as_str() == a.method && a.path.matches(raw_path) && query_ok(a.query, raw_query)
        })
}

/// Whether `query` has a parameter named `key` (exactly, or once
/// percent-decoded), split on `&` and `;` (D4, Google route). The name is
/// case-sensitive, as URL query names are.
pub fn query_has_key(query: &str) -> bool {
    query.split(['&', ';']).any(|param| {
        let name = param.split('=').next().unwrap_or("");
        name == "key" || percent_decode(name.as_bytes()) == b"key"
    })
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// `s` with each valid `%XX` decoded; anything else is kept as it is.
pub fn percent_decode(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' && i + 2 < s.len() {
            if let (Some(h), Some(l)) = (hex(s[i + 1]), hex(s[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(s[i]);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::box_gateway::model::rewrite_request;
    use http::{HeaderMap, Request};

    /// One line per allowed shape, for pinning.
    fn shapes(r: &Route) -> Vec<String> {
        r.allow
            .iter()
            .map(|a| {
                let path = match a.path {
                    PathRule::Exact(p) => p.to_string(),
                    PathRule::Id { prefix, suffix } => format!("{prefix}{{ID}}{suffix}"),
                };
                let q: Vec<String> = a
                    .query
                    .iter()
                    .map(|p| {
                        let v = match p.value {
                            ValueRule::Exact(v) => v.to_string(),
                            ValueRule::Digits(n) => format!("<1-{n} digits>"),
                            ValueRule::Version => "<version>".into(),
                        };
                        let req = if p.required { "!" } else { "?" };
                        format!("{}={v}{req}", p.name)
                    })
                    .collect();
                format!("{} {path} [{}]", a.method, q.join(" "))
            })
            .collect()
    }

    #[test]
    fn route_table_is_pinned() {
        let a = route(Provider::Anthropic);
        assert_eq!(a.provider, Provider::Anthropic);
        assert_eq!(a.host, "api.anthropic.com");
        assert_eq!(a.services, ["box-model-anthropic", "box-model"]);
        assert_eq!(
            shapes(a),
            [
                "POST /v1/messages [beta=true?]",
                "POST /v1/messages/count_tokens [beta=true?]",
                "GET /v1/models [beta=true? limit=<1-4 digits>?]",
                "GET /v1/models/{ID} [beta=true?]",
            ]
        );
        let o = route(Provider::OpenAi);
        assert_eq!(o.provider, Provider::OpenAi);
        assert_eq!(o.host, "api.openai.com");
        assert_eq!(o.services, ["box-model-openai"]);
        assert_eq!(
            shapes(o),
            [
                "POST /v1/responses []",
                "GET /v1/models [client_version=<version>?]",
                "GET /v1/models/{ID} []",
            ]
        );
        let g = route(Provider::Google);
        assert_eq!(g.provider, Provider::Google);
        assert_eq!(g.host, "generativelanguage.googleapis.com");
        assert_eq!(g.services, ["box-model-google"]);
        assert_eq!(
            shapes(g),
            [
                "POST /v1beta/models/{ID}:streamGenerateContent [alt=sse!]",
                "POST /v1beta/models/{ID}:generateContent []",
                "POST /v1beta/models/{ID}:countTokens []",
            ]
        );

        let h = |c| {
            let (n, b) = cred_header(c);
            (n.as_str().to_string(), b)
        };
        assert_eq!(h(ModelCred::AnthropicApiKey), ("x-api-key".into(), false));
        assert_eq!(
            h(ModelCred::AnthropicSubscription),
            ("authorization".into(), true)
        );
        assert_eq!(h(ModelCred::OpenAiApiKey), ("authorization".into(), true));
        assert_eq!(h(ModelCred::GoogleApiKey), ("x-goog-api-key".into(), false));

        assert_eq!(provider_of(ModelCred::AnthropicApiKey), Provider::Anthropic);
        assert_eq!(
            provider_of(ModelCred::AnthropicSubscription),
            Provider::Anthropic
        );
        assert_eq!(provider_of(ModelCred::OpenAiApiKey), Provider::OpenAi);
        assert_eq!(provider_of(ModelCred::GoogleApiKey), Provider::Google);
    }

    /// `METHOD target` on `r`.
    fn ok(r: &Route, req: &str) -> bool {
        let (m, target) = req.split_once(' ').unwrap();
        let (path, query) = match target.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (target, None),
        };
        allowed(r, &Method::from_bytes(m.as_bytes()).unwrap(), path, query)
    }

    #[test]
    fn path_rules() {
        // D4 tricks: never plain, so never allowed on any route.
        let tricks = [
            "/v1/messages/../x",
            "/v1/messages/./x",
            "/v1/messages/..",
            "/v1/messages/.",
            "/v1/messages/%2E%2E/x",
            "/v1/messages/%2e%2e/x",
            "/v1/messages/%2e./x",
            "/v1/models/%2e%2e/files",
            "/v1/messages/x/../batches",
            "/v1//messages",
            "//v1/messages",
            "/v1/messages/",
            "/v1/messages%2fx",
            "/v1/messages%2Fx",
            "/v1/messages%5cx",
            "/v1/messages%5Cx",
            "/v1/messages\\x",
            "/v1/messages\0x",
            "/v1/messages%00x",
            "/v1/messages x",
            "/v1/messages\tx",
            "/v1/messages/\u{e9}",
            "/v1/messages\u{7f}",
            "/",
            "",
            "v1/messages",
        ];
        for t in tricks {
            assert!(!path_plain(t), "{t:?} is plain");
            for r in [&ANTHROPIC, &OPENAI, &GOOGLE] {
                for m in [Method::GET, Method::POST] {
                    assert!(!allowed(r, &m, t, None), "{t:?} allowed on {}", r.host);
                }
            }
        }
        for p in [
            "/v1/messages",
            "/v1/messages/count_tokens",
            "/v1beta/models/m:streamGenerateContent",
            "/v1/messages/%41x",
            "/x.y/z..w/.a",
        ] {
            assert!(path_plain(p), "{p:?} is not plain");
        }
        let id128 = "a".repeat(128);
        let id129 = "a".repeat(129);
        let pass = [
            (&ANTHROPIC, "POST /v1/messages".to_string()),
            (&ANTHROPIC, "POST /v1/messages?beta=true".into()),
            (&ANTHROPIC, "POST /v1/messages/count_tokens".into()),
            (
                &ANTHROPIC,
                "POST /v1/messages/count_tokens?beta=true".into(),
            ),
            (&ANTHROPIC, "GET /v1/models".into()),
            (&ANTHROPIC, "GET /v1/models?beta=true".into()),
            (&ANTHROPIC, "GET /v1/models?limit=1000&beta=true".into()),
            (&ANTHROPIC, "GET /v1/models?beta=true&limit=5".into()),
            (&ANTHROPIC, "GET /v1/models/claude-x.y_z-1".into()),
            (&ANTHROPIC, "GET /v1/models/claude-x?beta=true".into()),
            (&ANTHROPIC, format!("GET /v1/models/{id128}")),
            (&OPENAI, "POST /v1/responses".into()),
            (&OPENAI, "GET /v1/models".into()),
            (&OPENAI, "GET /v1/models?client_version=0.169.0".into()),
            (&OPENAI, "GET /v1/models?client_version=1.2.3-beta+4".into()),
            (&OPENAI, "GET /v1/models/gpt-5.1".into()),
            (
                &GOOGLE,
                "POST /v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse".into(),
            ),
            (&GOOGLE, "POST /v1beta/models/m:generateContent".into()),
            (&GOOGLE, "POST /v1beta/models/m:countTokens".into()),
        ];
        for (r, req) in &pass {
            assert!(ok(r, req), "{req} refused on {}", r.host);
        }
        let refuse = [
            (&ANTHROPIC, "POST /v1/messages/batches".to_string()),
            (&ANTHROPIC, "POST /v1/messages/batches/x".into()),
            (&ANTHROPIC, "GET /v1/messages/batches".into()),
            (&ANTHROPIC, "POST /v1/messagesX".into()),
            (&ANTHROPIC, "GET /v1/messages".into()),
            (&ANTHROPIC, "POST /v1/models".into()),
            (&ANTHROPIC, "HEAD /api/hello".into()),
            (&ANTHROPIC, "GET /api/hello".into()),
            (&ANTHROPIC, "POST /v1/responses".into()),
            (&ANTHROPIC, "POST /v1/messages?x=1".into()),
            (&ANTHROPIC, "POST /v1/messages?beta=true&beta=true".into()),
            (&ANTHROPIC, "POST /v1/messages?beta=false".into()),
            (&ANTHROPIC, "POST /v1/messages?beta".into()),
            (&ANTHROPIC, "POST /v1/messages?".into()),
            (&ANTHROPIC, "POST /v1/messages?beta=true&".into()),
            (&ANTHROPIC, "POST /v1/messages?beta=true;x=1".into()),
            (&ANTHROPIC, "POST /v1/messages?%62eta=true".into()),
            (&ANTHROPIC, "GET /v1/models?limit=12345".into()),
            (&ANTHROPIC, "GET /v1/models?limit=".into()),
            (&ANTHROPIC, "GET /v1/models?limit=1a".into()),
            (&ANTHROPIC, "GET /v1/models?after_id=x".into()),
            (&ANTHROPIC, "GET /v1/models/a$b".into()),
            (&ANTHROPIC, "GET /v1/models/a:b".into()),
            (&ANTHROPIC, format!("GET /v1/models/{id129}")),
            (&ANTHROPIC, "GET /v1/models/a/b".into()),
            (&ANTHROPIC, "GET /v1/models/".into()),
            (&ANTHROPIC, "GET /v1/models/..".into()),
            (&ANTHROPIC, "GET /v1/models/%2e".into()),
            (&ANTHROPIC, "GET /v1/models/a%41".into()),
            (&ANTHROPIC, "POST //v1/messages".into()),
            (&ANTHROPIC, "POST /v1/messages%2Fbatches".into()),
            (&ANTHROPIC, "POST /v1/messages/%2E%2E/x".into()),
            (&OPENAI, "GET /v1/responses/abc".into()),
            (&OPENAI, "DELETE /v1/responses/abc".into()),
            (&OPENAI, "POST /v1/responses/compact".into()),
            (&OPENAI, "GET /v1/responses".into()),
            (&OPENAI, "POST /v1/responses?stream=true".into()),
            (&OPENAI, "POST /v1/messages".into()),
            (&OPENAI, "POST /v1/files".into()),
            (&OPENAI, "POST /v1/chat/completions".into()),
            (&OPENAI, "GET /v1/models?client_version=a b".into()),
            (
                &OPENAI,
                format!("GET /v1/models?client_version={}", "1".repeat(33)),
            ),
            (&OPENAI, "GET /v1/models?client_version=".into()),
            (
                &OPENAI,
                "GET /v1/models?client_version=1&client_version=2".into(),
            ),
            (&OPENAI, "GET /v1/models/m?client_version=1".into()),
            (&GOOGLE, "GET /v1beta/models".into()),
            (&GOOGLE, "GET /v1beta/models/m".into()),
            (
                &GOOGLE,
                "POST /v1beta/models/m:streamGenerateContent".into(),
            ),
            (
                &GOOGLE,
                "POST /v1beta/models/m:streamGenerateContent?alt=json".into(),
            ),
            (
                &GOOGLE,
                "POST /v1beta/models/m:streamGenerateContent?alt=sse&alt=sse".into(),
            ),
            (
                &GOOGLE,
                "POST /v1beta/models/m:streamGenerateContent?alt=sse&x=1".into(),
            ),
            (
                &GOOGLE,
                "POST /v1beta/models/m:generateContent?alt=sse".into(),
            ),
            (&GOOGLE, "GET /v1beta/models/m:generateContent".into()),
            (&GOOGLE, "POST /v1beta/models/:generateContent".into()),
            (&GOOGLE, "POST /v1beta/models/a:b:generateContent".into()),
            (&GOOGLE, "POST /v1beta/models/m:generateContentX".into()),
            (&GOOGLE, "POST /v1beta/modelsX".into()),
            (&GOOGLE, "POST /upload/v1beta/files".into()),
            (&GOOGLE, "POST /v1beta/files".into()),
            (&GOOGLE, "POST /v1/models/m:generateContent".into()),
            (&GOOGLE, "POST /v1beta/tunedModels/m:generateContent".into()),
        ];
        for (r, req) in &refuse {
            assert!(!ok(r, req), "{req} allowed on {}", r.host);
        }
        assert!(is_id("a") && is_id(&id128) && is_id("A.b_c-9"));
        for bad in ["", ".", "..", "a/b", "a:b", "a%41", "a b", &id129] {
            assert!(!is_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn query_key_rules() {
        for q in [
            "key=x",
            "alt=sse&key=x",
            "alt=sse&key",
            "key",
            "a=1;key=2",
            "%6Bey=x",
            "%6bey=x",
            "k%65y=x",
            "%6B%65%79=x",
        ] {
            assert!(query_has_key(q), "{q}");
        }
        for q in [
            "", "alt=sse", "keys=x", "akey=x", "Key=x", "KEY=x", "x=key", "monkey=1",
        ] {
            assert!(!query_has_key(q), "{q}");
        }
        assert_eq!(percent_decode(b"%41%2f%zz%4"), b"A/%zz%4".to_vec());
    }

    fn names(h: &HeaderMap) -> Vec<String> {
        let mut v: Vec<String> = h
            .iter()
            .map(|(k, v)| format!("{k}: {}", v.to_str().unwrap()))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn rewrite_request_per_cred_is_pinned() {
        const REAL: &str = concat!("real", "-", "key", "-", "0123");
        let all = [
            ("x-api-key", "box-a"),
            ("authorization", "Bearer box-b"),
            ("x-goog-api-key", "box-c"),
            ("openai-organization", "org-x"),
            ("openai-project", "proj-x"),
            ("x-goog-user-project", "gp-x"),
            ("cookie", "a=b"),
            ("host", "evil.test"),
            ("content-type", "application/json"),
            ("openai-beta", "responses=v1"),
            ("x-goog-api-client", "gl-node/22"),
        ];
        let rest = |host: &str, cred: String| {
            let mut v = vec![
                "content-type: application/json".to_string(),
                format!("host: {host}"),
                "openai-beta: responses=v1".into(),
                "x-goog-api-client: gl-node/22".into(),
                cred,
            ];
            v.sort();
            v
        };
        let cases = [
            (
                ModelCred::AnthropicApiKey,
                "x-api-key",
                rest("api.anthropic.com", format!("x-api-key: {REAL}")),
            ),
            (
                ModelCred::AnthropicSubscription,
                "authorization",
                rest("api.anthropic.com", format!("authorization: Bearer {REAL}")),
            ),
            (
                ModelCred::OpenAiApiKey,
                "authorization",
                rest("api.openai.com", format!("authorization: Bearer {REAL}")),
            ),
            (
                ModelCred::GoogleApiKey,
                "x-goog-api-key",
                rest(
                    "generativelanguage.googleapis.com",
                    format!("x-goog-api-key: {REAL}"),
                ),
            ),
        ];
        for (cred, header, want) in cases {
            let mut b = Request::builder()
                .method("POST")
                .uri("/v1beta/models/m:streamGenerateContent?alt=sse");
            for (k, v) in all {
                b = b.header(k, v);
            }
            let mut p = b.body(()).unwrap().into_parts().0;
            rewrite_request(&mut p, cred, REAL).unwrap();
            assert_eq!(names(&p.headers), want, "{cred:?}");
            assert!(p.headers[header].is_sensitive(), "{cred:?}");
            assert_eq!(p.headers.get_all(header).iter().count(), 1, "{cred:?}");
            // The target is untouched: the key never goes in the URL.
            assert_eq!(p.uri, "/v1beta/models/m:streamGenerateContent?alt=sse");
        }
    }
}
