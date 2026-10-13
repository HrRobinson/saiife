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
        (r"([A-Za-z][A-Za-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@", "${1}[MASKED]@"),
        (r#"(?i)(authorization:\s*(?:bearer\s+|basic\s+|token\s+)?)[^\s'"]+"#, "${1}[MASKED]"),
        (r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]+", "${1}[MASKED]"),
        (r#"(?i)(--(?:password|passwd|token|secret|api-key|apikey)(?:=|\s+))(?:'[^']*'|"[^"]*"|\S+)"#, "${1}[MASKED]"),
        (r#"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_KEY)[A-Z0-9_]*=)(?:'[^']*'|"[^"]*"|\S+)"#, "${1}[MASKED]"),
        (r"\b(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{20,}\b", MASK),
        (r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", MASK),
        (r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", MASK),
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
    fn private_key_block() {
        let input = "echo '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END OPENSSH PRIVATE KEY-----' > k";
        assert_eq!(mask(input), "echo '[MASKED]' > k");
        let unterminated = "cat <<EOF\n-----BEGIN RSA PRIVATE KEY-----\nAAAA";
        assert_eq!(mask(unterminated), "cat <<EOF\n[MASKED]");
    }
}
