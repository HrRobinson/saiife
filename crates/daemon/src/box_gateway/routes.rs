//! The model forwarder's route table (plan 42 D1, D4): per provider, the one
//! upstream host (port 443), the vault services a key must allow and the
//! paths forwarded. Pure: no I/O here; [`super::model`] is the only place
//! that touches the network.
//!
//! The box never picks its route: the forwarder takes it from the box's
//! template (`AgentKind::provider()`) on every request.

use http::header::{HeaderName, AUTHORIZATION};
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
    /// Segment prefixes of the raw origin-form path (before any query).
    pub paths: &'static [&'static str],
}

pub const ANTHROPIC: Route = Route {
    provider: Provider::Anthropic,
    host: "api.anthropic.com",
    // TODO(release): drop the legacy "box-model" alias (owner decision OD4, plan 42 D6)
    services: &["box-model-anthropic", "box-model"],
    paths: &["/v1/messages", "/v1/models"],
};

pub const OPENAI: Route = Route {
    provider: Provider::OpenAi,
    host: "api.openai.com",
    services: &["box-model-openai"],
    paths: &["/v1/responses", "/v1/models"],
};

pub const GOOGLE: Route = Route {
    provider: Provider::Google,
    host: "generativelanguage.googleapis.com",
    services: &["box-model-google"],
    paths: &["/v1beta/models", "/v1/models"],
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

/// Whether `raw_path` is plain and equals one of the route's prefixes or
/// continues one with `/` (D1).
pub fn path_allowed(route: &Route, raw_path: &str) -> bool {
    path_plain(raw_path)
        && route.paths.iter().any(|p| {
            raw_path
                .strip_prefix(p)
                .is_some_and(|r| r.is_empty() || r.starts_with('/'))
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

    #[test]
    fn route_table_is_pinned() {
        let a = route(Provider::Anthropic);
        assert_eq!(a.provider, Provider::Anthropic);
        assert_eq!(a.host, "api.anthropic.com");
        assert_eq!(a.services, ["box-model-anthropic", "box-model"]);
        assert_eq!(a.paths, ["/v1/messages", "/v1/models"]);
        let o = route(Provider::OpenAi);
        assert_eq!(o.provider, Provider::OpenAi);
        assert_eq!(o.host, "api.openai.com");
        assert_eq!(o.services, ["box-model-openai"]);
        assert_eq!(o.paths, ["/v1/responses", "/v1/models"]);
        let g = route(Provider::Google);
        assert_eq!(g.provider, Provider::Google);
        assert_eq!(g.host, "generativelanguage.googleapis.com");
        assert_eq!(g.services, ["box-model-google"]);
        assert_eq!(g.paths, ["/v1beta/models", "/v1/models"]);

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
                assert!(!path_allowed(r, t), "{t:?} allowed on {}", r.host);
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
        let allowed: [(&Route, &str); 13] = [
            (&ANTHROPIC, "/v1/messages"),
            (&ANTHROPIC, "/v1/messages/count_tokens"),
            (&ANTHROPIC, "/v1/models"),
            (&ANTHROPIC, "/v1/models/claude-x"),
            (&OPENAI, "/v1/responses"),
            (&OPENAI, "/v1/responses/compact"),
            (&OPENAI, "/v1/models"),
            (&GOOGLE, "/v1beta/models"),
            (&GOOGLE, "/v1beta/models/m:streamGenerateContent"),
            (&GOOGLE, "/v1beta/models/m:generateContent"),
            (&GOOGLE, "/v1beta/models/m:countTokens"),
            (&GOOGLE, "/v1/models"),
            (&GOOGLE, "/v1/models/m"),
        ];
        for (r, p) in allowed {
            assert!(path_allowed(r, p), "{p} refused on {}", r.host);
        }
        let refused: [(&Route, &str); 16] = [
            (&ANTHROPIC, "/v1/messagesX"),
            (&ANTHROPIC, "/v1/models-x"),
            (&ANTHROPIC, "/v1/responses"),
            (&ANTHROPIC, "/api/hello"),
            (&ANTHROPIC, "/v1"),
            (&ANTHROPIC, "/V1/messages"),
            (&OPENAI, "/v1/messages"),
            (&OPENAI, "/v1/files"),
            (&OPENAI, "/v1/responsesX"),
            (&OPENAI, "/v1/chat/completions"),
            (&GOOGLE, "/v1beta/modelsX"),
            (&GOOGLE, "/upload/v1beta/files"),
            (&GOOGLE, "/v1beta/files"),
            (&GOOGLE, "/v1/messages"),
            (&GOOGLE, "/v1beta/tunedModels"),
            (&GOOGLE, "/v1beta"),
        ];
        for (r, p) in refused {
            assert!(!path_allowed(r, p), "{p} allowed on {}", r.host);
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
