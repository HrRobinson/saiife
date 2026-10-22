//! What `saiife doctor` found: one [`Check`] per line, the exit code, and
//! the text and JSON forms (spec §6.16).

use saiife_audit::text::sanitize;
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Warn,
    Fail,
    /// Reported, never counted.
    Info,
}

impl Status {
    fn tag(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
            Status::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub id: String,
    pub status: Status,
    pub title: String,
    pub detail: String,
}

impl Check {
    pub fn new(
        id: impl Into<String>,
        status: Status,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> Check {
        Check {
            id: id.into(),
            status,
            title: title.into(),
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    fn count(&self, s: Status) -> usize {
        self.checks.iter().filter(|c| c.status == s).count()
    }

    /// 2 on any failure, else 1 on any warning, else 0. `Info` never counts.
    pub fn exit_code(&self) -> u8 {
        if self.count(Status::Fail) > 0 {
            2
        } else if self.count(Status::Warn) > 0 {
            1
        } else {
            0
        }
    }

    /// `{"saiife_doctor":1,"exit":<n>,"checks":[{"id","status","title","detail"}]}`.
    pub fn to_json(&self) -> Value {
        json!({
            "saiife_doctor": 1,
            "exit": self.exit_code(),
            "checks": self.checks,
        })
    }

    /// One line per check, then `doctor: <n> failures, <m> warnings`. Ids,
    /// titles and details carry host-derived text (file names, config
    /// errors, server names), so control and invisible characters are
    /// escaped and every check stays on one line.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for c in &self.checks {
            out.push_str(c.status.tag());
            out.push_str("  ");
            out.push_str(&sanitize(&c.id));
            out.push_str("  ");
            out.push_str(&sanitize(&c.title));
            if !c.detail.is_empty() {
                out.push_str(": ");
                out.push_str(&sanitize(&c.detail));
            }
            out.push('\n');
        }
        out.push_str(&format!(
            "doctor: {} failures, {} warnings\n",
            self.count(Status::Fail),
            self.count(Status::Warn)
        ));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(statuses: &[Status]) -> Report {
        Report {
            checks: statuses
                .iter()
                .enumerate()
                .map(|(i, s)| Check::new(format!("c{i}"), *s, "title", ""))
                .collect(),
        }
    }

    #[test]
    fn exit_code_rules() {
        assert_eq!(report(&[]).exit_code(), 0);
        assert_eq!(report(&[Status::Info, Status::Info]).exit_code(), 0);
        assert_eq!(report(&[Status::Pass, Status::Info]).exit_code(), 0);
        assert_eq!(report(&[Status::Pass, Status::Warn]).exit_code(), 1);
        assert_eq!(report(&[Status::Warn, Status::Fail]).exit_code(), 2);
        assert_eq!(report(&[Status::Fail, Status::Info]).exit_code(), 2);
    }

    #[test]
    fn json_shape() {
        let r = Report {
            checks: vec![
                Check::new("keys", Status::Pass, "audit signing key", ""),
                Check::new("mcp.x", Status::Warn, "MCP server x bypasses", "d"),
            ],
        };
        assert_eq!(
            r.to_json(),
            json!({
                "saiife_doctor": 1,
                "exit": 1,
                "checks": [
                    {"id": "keys", "status": "pass", "title": "audit signing key", "detail": ""},
                    {"id": "mcp.x", "status": "warn", "title": "MCP server x bypasses", "detail": "d"},
                ]
            })
        );
        let info = Check::new("i", Status::Info, "t", "");
        assert_eq!(serde_json::to_value(&info).unwrap()["status"], "info");
        let fail = Check::new("f", Status::Fail, "t", "");
        assert_eq!(serde_json::to_value(&fail).unwrap()["status"], "fail");
    }

    #[test]
    fn text_escapes_control_characters() {
        let r = Report {
            checks: vec![Check::new(
                "mcp.\x1b[31mx",
                Status::Warn,
                "title\u{202E}",
                "a\nb\x07",
            )],
        };
        let text = r.to_text();
        assert!(!text.contains('\x1b') && !text.contains('\x07'), "{text}");
        assert!(!text.contains('\u{202E}'), "{text}");
        assert_eq!(text.lines().count(), 2, "{text}");
        assert!(text.contains("\\x1b[31m"), "{text}");
        let json = serde_json::to_string(&r.to_json()).unwrap();
        assert!(!json.contains('\x1b') && json.contains("\\u001b"), "{json}");
    }

    #[test]
    fn text_lines() {
        let r = Report {
            checks: vec![
                Check::new("keys", Status::Pass, "audit signing key", ""),
                Check::new(
                    "daemon.unit",
                    Status::Fail,
                    "saiifed.service active",
                    "inactive",
                ),
                Check::new("vault.key", Status::Info, "vault key", "plain"),
            ],
        };
        assert_eq!(
            r.to_text(),
            "PASS  keys  audit signing key\n\
             FAIL  daemon.unit  saiifed.service active: inactive\n\
             INFO  vault.key  vault key: plain\n\
             doctor: 1 failures, 0 warnings\n"
        );
    }
}
