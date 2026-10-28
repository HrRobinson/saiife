//! Secret masking applied to every record's `input` before it is written
//! (spec §6.3). Plaintext secrets never reach disk.

use std::sync::LazyLock;

use regex::Regex;

pub const MASK: &str = "[MASKED]";

/// `(pattern, replacement)`, applied in order. Order matters: whole private
/// key blocks first, then structured forms that keep a visible prefix
/// (URL scheme, header name, flag name, variable name), then bare tokens.
static RULES: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    [
        (r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\z)", MASK),
        // Whole userinfo, greedy up to the last '@' before the path/query
        // (`user:p@ss@host`, token-only `TOKEN@host`).
        (r#"([A-Za-z][A-Za-z0-9+.-]*://)(?:(?:[^/?#\s"'`<>]|["'`<>]+[^/?#\s"'`<>,}\]);&|])+["'`<>]*|["'`<>]+)@"#, "${1}[MASKED]@"),
        (r#"(?i)(authorization:\s*(?:bearer\s+|basic\s+|token\s+)?)[^\s'"]+"#, "${1}[MASKED]"),
        (r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]+", "${1}[MASKED]"),
        (r#"(?i)(--(?:[a-z0-9]+-)*(?:password|passwd|token|secret|secret-key|api-key|apikey)(?:=|\s+))(?:'[^']*'|"[^"]*"|\S+)"#, "${1}[MASKED]"),
        (r#"(\b(?i:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)\b(?:'[^']*'|"(?:\\.|[^"\\])*"|\\\n|[^|;&\n])*?\s-p)(?:'[^']*'|"(?:\\.|[^"\\])*"|\\.|\S)+"#, "${1}[MASKED]"),
        (r#"(?i)(\baws\s+configure\s+set\s+(?:[A-Za-z0-9_-]+\.)*(?:aws_secret_access_key|aws_session_token)\s+)(?:'[^']*'|"[^"]*"|\S+)"#, "${1}[MASKED]"),
        (r#"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_KEY)[A-Z0-9_]*=)(?:'[^']*'|"[^"]*"|\S+)"#, "${1}[MASKED]"),
        // No leading `\b`: a token glued to an identifier (`X_ghp_…`) still counts.
        (r"(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{20,}\b", MASK),
        (r"github_pat_[A-Za-z0-9_]{20,}\b", MASK),
        // saiife's own gateway bearer tokens (`saiife api token`).
        (r"saiife_gw_[A-Za-z0-9_-]{20,}", MASK),
        (r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", MASK),
        // Wave 2 and 3 connector services, one alternation (one extra pass
        // on the hook path). The webhook forms keep their visible host path
        // prefix and mask the secret remainder.
        (
            concat!(
                r"(?i:(hooks\.slack(?:-gov)?\.com/(?:services|triggers|workflows)/|discord(?:app)?\.com/api/(?:v\d+/)?webhooks/[0-9]+/))[A-Za-z0-9_/-]+",
                r"|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}",
                r"|whsec_[A-Za-z0-9]{24,}",
                r"|xox[abcdeposr]-[A-Za-z0-9-]{10,}",
                r"|xoxe(?:\.xox[a-z])?-[A-Za-z0-9-]{10,}",
                r"|xapp-[A-Za-z0-9-]{10,}",
                r"|lin_(?:api|oauth)_[A-Za-z0-9]{32,}",
                r"|sntry[su]_[A-Za-z0-9+/=_-]{20,}",
                r"|gl(?:pat|dt|ptt|rt|oas|cbt|imt|agent|soat|ft)-[A-Za-z0-9_.-]{20,}",
                r"|[MNO][A-Za-z0-9_-]{23,27}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,38}",
                r"|00D[A-Za-z0-9]{12,15}![A-Za-z0-9._]{80,}",
                r"|dG9rO[A-Za-z0-9+/=_-]{20,}",
                r"|pat[A-Za-z0-9]{14}\.[a-f0-9]{64}",
                r"|c[ks]_[a-f0-9]{40}",
            ),
            // `${1}` keeps the webhook URL prefix. In every other branch group 1
            // did not participate, so it expands to the empty string and the
            // whole match becomes `[MASKED]`.
            "${1}[MASKED]",
        ),
        // Cloud key shapes, two alternations (two extra passes). No leading
        // `\b`: a token glued to an identifier still counts.
        (
            concat!(
                r"ya29\.[A-Za-z0-9_-]{20,}",
                r"|AIza[0-9A-Za-z_-]{35}",
                r"|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
            ),
            MASK,
        ),
        // Key names keep their prefix (case-insensitive; the JSON quotes may
        // be backslash-escaped when the document is itself a string).
        (
            concat!(
                r#"((?i:"#,
                r#"\\?"(?:SecretAccessKey|SessionToken|secret_access_key|session_token|private_key|client_secret|access_token|refresh_token)\\?"\s*:\s*\\?""#,
                r#"|<(?:SecretAccessKey|SessionToken)>"#,
                r#"|AccountKey=|SharedAccessSignature="#,
                r#"|[?&]sig="#,
                r#"))[^"<;&\s]{8,}"#,
            ),
            "${1}[MASKED]",
        ),
    ]
    .into_iter()
    .map(|(p, r)| (Regex::new(p).expect("mask pattern compiles"), r))
    .collect()
});

/// Replace anything that looks like a secret with `[MASKED]`.
pub fn mask(input: &str) -> String {
    let mut out = input.to_string();
    for (re, replacement) in RULES.iter() {
        if re.is_match(&out) {
            out = re.replace_all(&out, *replacement).into_owned();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_tokens() {
        let tok = format!("ghp_{}", "a".repeat(36));
        assert_eq!(
            mask(&format!("gh auth login --with-token {tok}")),
            "gh auth login --with-token [MASKED]"
        );
        let pat = format!("github_pat_{}", "B".repeat(40));
        assert_eq!(mask(&format!("echo {pat}")), "echo [MASKED]");
        let gho = format!("gho_{}", "c".repeat(36));
        assert_eq!(mask(&gho), "[MASKED]");
    }

    #[test]
    fn saiife_gateway_tokens() {
        let tok = format!("saiife_gw_{}", "aZ09_-".repeat(7));
        assert_eq!(mask(&format!("curl -H x:{tok} u")), "curl -H x:[MASKED] u");
        assert_eq!(
            mask(&format!("/v1/proxy/s/a?t={tok}&b=1")),
            "/v1/proxy/s/a?t=[MASKED]&b=1"
        );
        // Too short to be one.
        assert_eq!(mask("saiife_gw_short"), "saiife_gw_short");
    }

    #[test]
    fn aws_access_key_id_and_secret_assignment() {
        assert_eq!(
            mask("export AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP"),
            "export AWS_ACCESS_KEY_ID=[MASKED]"
        );
        assert_eq!(mask("echo ASIAABCDEFGHIJKLMNOP"), "echo [MASKED]");
        assert_eq!(
            mask("aws_secret_access_key=wJalrXUtnFEMI/K7MDENG"),
            "aws_secret_access_key=[MASKED]"
        );
    }

    #[test]
    fn authorization_and_bearer() {
        assert_eq!(
            mask(r#"curl -H "Authorization: Bearer abc.def.ghi" https://x"#),
            r#"curl -H "Authorization: Bearer [MASKED]" https://x"#
        );
        assert_eq!(
            mask("curl -H 'authorization: token xyz123' u"),
            "curl -H 'authorization: token [MASKED]' u"
        );
        assert_eq!(mask("bearer s3cr3t-value"), "bearer [MASKED]");
    }

    #[test]
    fn secret_flags_equals_and_space_forms() {
        assert_eq!(
            mask("mysql --password=hunter2 db"),
            "mysql --password=[MASKED] db"
        );
        assert_eq!(mask("tool --token abc123 run"), "tool --token [MASKED] run");
        assert_eq!(
            mask("tool --api-key 'k e y' run"),
            "tool --api-key [MASKED] run"
        );
        assert_eq!(mask(r#"tool --secret="x y""#), "tool --secret=[MASKED]");
    }

    #[test]
    fn secret_flag_lookalikes_are_not_masked() {
        assert_eq!(mask("tool --token-file ./path"), "tool --token-file ./path");
        assert_eq!(mask("git status"), "git status");
        assert_eq!(mask("rm -rf /"), "rm -rf /");
    }

    #[test]
    fn env_assignments_with_secret_names() {
        assert_eq!(mask("API_KEY=abc ./run"), "API_KEY=[MASKED] ./run");
        assert_eq!(
            mask("export DB_PASSWORD='p w'"),
            "export DB_PASSWORD=[MASKED]"
        );
        assert_eq!(mask("MY_SECRET_TOKEN=x"), "MY_SECRET_TOKEN=[MASKED]");
        assert_eq!(mask("PATH=/usr/bin ls"), "PATH=/usr/bin ls");
    }

    #[test]
    fn url_credentials() {
        assert_eq!(
            mask("psql postgres://admin:pa55@db.local:5432/app"),
            "psql postgres://[MASKED]@db.local:5432/app"
        );
        assert_eq!(
            mask("git clone https://github.com/a/b"),
            "git clone https://github.com/a/b"
        );
    }

    #[test]
    fn hyphenated_secret_flags() {
        for flag in [
            "--access-token",
            "--auth-token",
            "--client-secret",
            "--secret-key",
            "--db-password",
            "--x-api-key",
        ] {
            assert_eq!(
                mask(&format!("tool {flag}=s3cr3t run")),
                format!("tool {flag}=[MASKED] run")
            );
            assert_eq!(
                mask(&format!("tool {flag} s3cr3t run")),
                format!("tool {flag} [MASKED] run")
            );
        }
        assert_eq!(mask("tool --token-file ./path"), "tool --token-file ./path");
        assert_eq!(
            mask("tool --access-token-file ./p"),
            "tool --access-token-file ./p"
        );
    }

    #[test]
    fn github_token_glued_to_identifier() {
        let tok = format!("ghp_{}", "a".repeat(36));
        assert_eq!(mask(&format!("echo X_{tok}")), "echo X_[MASKED]");
        let pat = format!("github_pat_{}", "B".repeat(40));
        assert_eq!(mask(&format!("echo V{pat}")), "echo V[MASKED]");
    }

    #[test]
    fn aws_configure_set_space_form() {
        assert_eq!(
            mask("aws configure set aws_secret_access_key wJalrXUtnFEMI/K7MDENG"),
            "aws configure set aws_secret_access_key [MASKED]"
        );
        assert_eq!(
            mask("aws configure set profile.dev.aws_session_token 'abc def'"),
            "aws configure set profile.dev.aws_session_token [MASKED]"
        );
        assert_eq!(
            mask("aws configure set region eu-west-1"),
            "aws configure set region eu-west-1"
        );
    }

    #[test]
    fn url_userinfo_is_masked_up_to_the_last_at() {
        assert_eq!(
            mask("curl https://user:p@ss@host/x"),
            "curl https://[MASKED]@host/x"
        );
        let tok = format!("ghp_{}", "a".repeat(36));
        assert_eq!(
            mask(&format!("git clone https://{tok}@github.com/a/b")),
            "git clone https://[MASKED]@github.com/a/b"
        );
        assert_eq!(
            mask("git push https://TOKEN123@host/r.git"),
            "git push https://[MASKED]@host/r.git"
        );
        assert_eq!(
            mask("git clone git@github.com:a/b"),
            "git clone git@github.com:a/b"
        );
        assert_eq!(
            mask("git clone https://github.com/a/b"),
            "git clone https://github.com/a/b"
        );
        assert_eq!(
            mask("curl 'https://h/p?to=a@b.c'"),
            "curl 'https://h/p?to=a@b.c'"
        );
    }

    #[test]
    fn mysql_attached_password() {
        assert_eq!(
            mask("mysql -uroot -phunter2 db"),
            "mysql -uroot -p[MASKED] db"
        );
        assert_eq!(mask("mysqldump -p'a b' db"), "mysqldump -p[MASKED] db");
        assert_eq!(
            mask("mariadb -h h -p\"x\" db"),
            "mariadb -h h -p[MASKED] db"
        );
        assert_eq!(
            mask("mysqladmin -psecret status"),
            "mysqladmin -p[MASKED] status"
        );
        // `-p` alone prompts; `-P` is the port; other tools keep -p.
        assert_eq!(mask("mysql -u root -p db"), "mysql -u root -p db");
        assert_eq!(mask("mysql -P 3306 db"), "mysql -P 3306 db");
        assert_eq!(mask("mkdir -p dir"), "mkdir -p dir");
        assert_eq!(mask("ssh -p2222 host"), "ssh -p2222 host");
    }

    #[test]
    fn mysql_password_edge_cases() {
        assert_eq!(
            mask(r#"mysql -e "a; b" -pSECRET"#),
            "mysql -e \"a; b\" -p[MASKED]"
        );
        assert_eq!(mask("mysql -p'ab'cd db"), "mysql -p[MASKED] db");
        assert_eq!(
            mask("mysql -e 'x|y' -pS db"),
            "mysql -e 'x|y' -p[MASKED] db"
        );
    }

    #[test]
    fn mysql_backslash_newline_continuation() {
        assert_eq!(
            mask("mysql -h db \\\n -u admin \\\n -pS3cret db"),
            "mysql -h db \\\n -u admin \\\n -p[MASKED] db"
        );
    }

    #[test]
    fn mysql_unpaired_quotes_and_escapes() {
        assert_eq!(
            mask(r#"mysql -e "a \" ; b" -pSECRET"#),
            r#"mysql -e "a \" ; b" -p[MASKED]"#
        );
        assert_eq!(
            mask("mysql -e 'unterminated -pSECRET"),
            "mysql -e 'unterminated -p[MASKED]"
        );
        assert_eq!(mask(r"mysql -pab\'cd db"), "mysql -p[MASKED] db");
    }

    #[test]
    fn url_password_ending_in_quote() {
        assert_eq!(mask("curl https://u:p'@h/x"), "curl https://[MASKED]@h/x");
        assert_eq!(mask("curl https://u:p\"@h/x"), "curl https://[MASKED]@h/x");
    }

    #[test]
    fn url_userinfo_with_quotes_in_password() {
        assert_eq!(
            mask("curl https://u:it's@host/x"),
            "curl https://[MASKED]@host/x"
        );
        assert_eq!(mask("curl https://u:p\"w@h/x"), "curl https://[MASKED]@h/x");
    }

    #[test]
    fn url_userinfo_does_not_cross_quotes() {
        let s = r#"{"u":"https://h","email":"a@b.c"}"#;
        assert_eq!(mask(s), s);
        assert_eq!(
            mask("curl 'https://h' -d 'x@y'"),
            "curl 'https://h' -d 'x@y'"
        );
        // A comma may be part of a password: still masked.
        assert_eq!(
            mask("curl https://u:p,w@host/x"),
            "curl https://[MASKED]@host/x"
        );
    }

    #[test]
    fn private_key_block() {
        let input = "echo '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END OPENSSH PRIVATE KEY-----' > k";
        assert_eq!(mask(input), "echo '[MASKED]' > k");
        let unterminated = "cat <<EOF\n-----BEGIN RSA PRIVATE KEY-----\nAAAA";
        assert_eq!(mask(unterminated), "cat <<EOF\n[MASKED]");
    }

    #[test]
    fn wave2_wave3_shapes_masked() {
        let al = |c: char, n: usize| c.to_string().repeat(n);
        let cases = [
            format!("{}_{}_{}", "sk", "live", al('a', 24)),
            format!("{}_{}_{}", "rk", "test", al('B', 20)),
            format!("{}_{}", "whsec", al('c', 32)),
            format!("{}-{}", "xoxb", "1234567890-abcdefghij"),
            format!("{}-{}", "xapp", "1-A0123456789-abcdef"),
            format!("{}_{}_{}", "lin", "api", al('d', 40)),
            format!("{}_{}", concat!("sntr", "ys"), al('e', 40)),
            format!("{}-{}", "glpat", al('f', 20)),
            format!("{}-{}", "gldt", al('g', 24)),
            format!("M{}.{}.{}", al('a', 24), al('b', 6), al('c', 30)),
            format!("00D{}!{}", al('A', 12), al('b', 90)),
            format!("{}{}", "dG9rO", al('h', 30)),
            format!("{}{}.{}", "pat", al('A', 14), al('a', 64)),
            format!("{}_{}", "ck", al('a', 40)),
            format!("{}_{}", "cs", al('0', 40)),
        ];
        for tok in cases {
            assert_eq!(mask(&format!("echo {tok} x")), "echo [MASKED] x", "{tok}");
        }
        let slack = format!("https://hooks.slack.com/services/T01/B02/{}", al('z', 24));
        assert_eq!(
            mask(&format!("curl {slack}")),
            "curl https://hooks.slack.com/services/[MASKED]"
        );
        let discord = format!("https://discord.com/api/webhooks/123456/{}", al('Q', 40));
        assert_eq!(
            mask(&format!("curl {discord}")),
            "curl https://discord.com/api/webhooks/123456/[MASKED]"
        );
        let app = format!("https://discordapp.com/api/webhooks/9/{}", al('Q', 40));
        assert_eq!(mask(&app), "https://discordapp.com/api/webhooks/9/[MASKED]");
    }

    #[test]
    fn near_misses_untouched() {
        let short_lin = format!("{}_{}_{}", "lin", "api", "a".repeat(10));
        for s in [
            "sk_live_short",
            "xoxb-",
            short_lin.as_str(),
            "pat",
            "a pat on the back",
            "https://hooks.slack.com/services/",
        ] {
            assert_eq!(mask(s), s);
        }
    }

    #[test]
    fn sentry_prefixes() {
        let body = "e".repeat(40);
        for pre in [concat!("sntr", "ys"), concat!("sntr", "yu")] {
            assert_eq!(mask(&format!("x {pre}_{body}")), "x [MASKED]");
        }
        let bad = format!("{}_{}", concat!("sntr", "y"), body);
        assert_eq!(mask(&bad), bad);
    }

    #[test]
    fn slack_discord_bypasses_closed() {
        let al = |c: char, n: usize| c.to_string().repeat(n);
        // Case-insensitive host, extra Slack paths, versioned Discord API.
        for u in [
            format!("HTTPS://Hooks.Slack.COM/Services/T1/B2/{}", al('z', 24)),
            format!("https://hooks.slack.com/triggers/T1/B2/{}", al('z', 24)),
            format!("https://hooks.slack.com/workflows/T1/B2/{}", al('z', 24)),
            format!("https://DISCORD.com/api/v10/webhooks/42/{}", al('Q', 40)),
        ] {
            let m = mask(&u);
            assert!(m.ends_with("/[MASKED]"), "{m}");
            assert!(!m.contains("zzzz") && !m.contains("QQQQ"), "{m}");
        }
        // Discord bot token starting with O, 7-char middle, 27-char first.
        for tok in [
            format!("O{}.{}.{}", al('a', 25), al('b', 6), al('c', 30)),
            format!("M{}.{}.{}", al('a', 26), al('b', 7), al('c', 38)),
        ] {
            assert_eq!(mask(&format!("t={tok} x")), "t=[MASKED] x");
        }
        // A token ending in `-` leaks nothing.
        let dash = format!("M{}.{}.{}-", al('a', 25), al('b', 6), al('c', 29));
        assert_eq!(mask(&format!("t={dash} x")), "t=[MASKED] x");
        // Slack refresh tokens.
        let plain = format!("{}-{}", concat!("xo", "xe"), "1-abcdefghijkl");
        let dotted = format!(
            "{}.{}-{}",
            concat!("xo", "xe"),
            concat!("xo", "xp"),
            "1-abcdefghijkl"
        );
        assert_eq!(mask(&plain), "[MASKED]");
        assert_eq!(mask(&dotted), "[MASKED]");
        // A dotted string starting with eyJ but without a second eyJ part is
        // not a JWT and stays untouched; a real JWT is masked by the cloud rule.
        let not_jwt = format!("eyJ{}.{}.{}", al('a', 30), al('b', 30), al('c', 30));
        assert_eq!(mask(&not_jwt), not_jwt);
        let jwt = format!("eyJ{}.eyJ{}.{}", al('a', 30), al('b', 30), al('c', 30));
        assert_eq!(mask(&jwt), "[MASKED]");
    }

    #[test]
    fn glued_and_extra_shapes() {
        let al = |c: char, n: usize| c.to_string().repeat(n);
        let disc = format!("M{}.{}.{}", al('a', 25), al('b', 6), al('c', 30));
        assert_eq!(mask(&format!("Bot%20{disc}")), "Bot%20[MASKED]");
        assert_eq!(mask(&format!("x_{disc}")), "x_[MASKED]");
        assert_eq!(mask(&format!("a\n{disc}")), "a\n[MASKED]");
        for pre in [concat!("xo", "xc"), concat!("xo", "xd")] {
            assert_eq!(mask(&format!("{pre}-{}", al('1', 12))), "[MASKED]");
        }
        let gl = |p: &str| format!("{p}-{}.01.{}", al('a', 12), al('z', 12));
        for p in [
            concat!("gl", "pat"),
            concat!("gl", "cbt"),
            concat!("gl", "imt"),
            concat!("gl", "agent"),
            concat!("gl", "soat"),
            concat!("gl", "ft"),
        ] {
            assert_eq!(mask(&format!("t {}", gl(p))), "t [MASKED]", "{p}");
        }
        let gov = format!("https://hooks.slack-gov.com/services/T1/B2/{}", al('z', 24));
        assert_eq!(mask(&gov), "https://hooks.slack-gov.com/services/[MASKED]");
    }

    #[test]
    fn gcp_access_token() {
        let tok = format!("{}{}", concat!("ya2", "9."), "A".repeat(40));
        assert_eq!(mask(&format!("tok={tok}")), "tok=[MASKED]");
        assert_eq!(mask(&format!("X{tok}-end")), "X[MASKED]");
        let short = concat!("ya2", "9.short");
        assert_eq!(mask(short), short);
    }

    #[test]
    fn google_api_key() {
        let key = format!("{}{}", concat!("AIz", "a"), "b".repeat(35));
        assert_eq!(mask(&format!("?key={key}&x=1")), "?key=[MASKED]&x=1");
        assert_eq!(mask(&format!("glued{key}")), "glued[MASKED]");
        // Too short.
        let short = format!("{}{}", concat!("AIz", "a"), "b".repeat(34));
        assert_eq!(mask(&short), short);
    }

    #[test]
    fn jwt_needs_three_parts() {
        let al = |c: char, n: usize| c.to_string().repeat(n);
        let jwt = format!("eyJ{}.eyJ{}.{}", al('a', 20), al('b', 20), al('c', 20));
        assert_eq!(mask(&format!("Authz {jwt} x")), "Authz [MASKED] x");
        assert_eq!(mask(&format!("v{jwt}")), "v[MASKED]");
        assert_eq!(mask(&format!("{jwt}.tail")), "[MASKED].tail");
        let two = format!("eyJ{}.eyJ{}", al('a', 20), al('b', 20));
        assert_eq!(mask(&two), two);
    }

    #[test]
    fn sa_json_private_key_escaped_newlines() {
        let pem = format!(
            "{}\\nMIIEvQIBADANBg\\n{}",
            concat!("-----BEGIN PRI", "VATE KEY-----"),
            concat!("-----END PRI", "VATE KEY-----")
        );
        let doc = format!(
            r#"{{"type":"service_account","private_key": "{pem}","client_email":"a@b.c"}}"#
        );
        let m = mask(&doc);
        assert!(!m.contains("MIIEvQ"), "{m}");
        assert!(m.contains(r#""private_key": "[MASKED]""#), "{m}");
        assert!(m.contains("client_email"), "{m}");
        // Case variant and a string-embedded (backslash-escaped) document.
        let m = mask(&format!(r#"{{\"PRIVATE_KEY\":\"{}\"}}"#, "Q".repeat(30)));
        assert!(!m.contains("QQQQ"), "{m}");
    }

    #[test]
    fn sts_xml_and_json_secret_and_token() {
        let v = "wJalrXUtnFEMIK7MDENGbPxRfiCY";
        assert_eq!(
            mask(&format!("<SecretAccessKey>{v}</SecretAccessKey>")),
            "<SecretAccessKey>[MASKED]</SecretAccessKey>"
        );
        assert_eq!(
            mask(&format!("<SessionToken>{v}==</SessionToken>")),
            "<SessionToken>[MASKED]</SessionToken>"
        );
        assert_eq!(
            mask(&format!(r#"{{"SecretAccessKey" : "{v}","x":1}}"#)),
            r#"{"SecretAccessKey" : "[MASKED]","x":1}"#
        );
        for k in [
            "session_token",
            "access_token",
            "refresh_token",
            "client_secret",
            "secret_access_key",
        ] {
            let m = mask(&format!(r#"{{"{k}":"{v}"}}"#));
            assert!(!m.contains(v), "{k}: {m}");
        }
        assert_eq!(
            mask("<sessiontoken>abcdefghijkl</sessiontoken>"),
            "<sessiontoken>[MASKED]</sessiontoken>"
        );
    }

    #[test]
    fn azure_account_key_and_sas() {
        let k = "Zm9vYmFyYmF6cXV4MTIzNA==";
        assert_eq!(
            mask(&format!(
                "DefaultEndpointsProtocol=https;AccountKey={k};EndpointSuffix=x"
            )),
            "DefaultEndpointsProtocol=https;AccountKey=[MASKED];EndpointSuffix=x"
        );
        assert_eq!(mask(&format!("accountkey={k}")), "accountkey=[MASKED]");
        assert_eq!(
            mask("SharedAccessSignature=sv=2020-08-04&sig=abcdefghij"),
            "SharedAccessSignature=[MASKED]&sig=[MASKED]"
        );
        assert_eq!(
            mask("https://a.blob.core.windows.net/c/b?sv=1&sig=AbCdEf%2Fgh%3D&se=2"),
            "https://a.blob.core.windows.net/c/b?sv=1&sig=[MASKED]&se=2"
        );
        assert_eq!(mask("u?SIG=AbCdEfGhIj"), "u?SIG=[MASKED]");
    }

    #[test]
    fn plain_words_untouched() {
        for s in [
            "the session token is rotated",
            "private_key",
            r#""private_key": "short""#,
            "design=ok&sig=short",
            "AccountKey=x",
            "<SessionToken>abc</SessionToken>",
            "eyJhbGciOi",
            "ya29 is a prefix",
            "AIza",
        ] {
            assert_eq!(mask(s), s);
        }
    }

    #[test]
    fn one_extra_pass_only() {
        // Twelve rules before wave 2/3, one wave 2/3 alternation, and two
        // cloud alternations.
        assert_eq!(RULES.len(), 15);
    }
}
