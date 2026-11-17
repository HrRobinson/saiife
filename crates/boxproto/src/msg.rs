//! The saiife-guest/1 messages.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

/// serde's internally tagged enums ignore extra keys on unit variants even with
/// `deny_unknown_fields`; this refuses them (the object must be exactly `{"t": <unit>}`).
fn no_extra_keys(v: &serde_json::Value, units: &[&str]) -> Result<(), String> {
    if let Some(o) = v.as_object() {
        if o.get("t")
            .and_then(|t| t.as_str())
            .is_some_and(|t| units.contains(&t))
            && o.len() != 1
        {
            return Err("unknown field".into());
        }
    }
    Ok(())
}

/// Guest to host, on the events port.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Event {
    Hello {
        proto: String,
        guest: String,
        uptime_ms: u64,
        set_up: bool,
    },
    Started,
    Activity,
    TurnFinished,
    /// FU1: the in-box guard hook ran `n` checks (n >= 1). A signal only:
    /// the guest, and an agent with sudo, can forge it.
    GuardChecks {
        n: u32,
    },
    Exited {
        code: Option<i32>,
    },
}

#[derive(Deserialize)]
#[serde(
    remote = "Event",
    tag = "t",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum EventDef {
    Hello {
        proto: String,
        guest: String,
        uptime_ms: u64,
        set_up: bool,
    },
    Started,
    Activity,
    TurnFinished,
    /// FU1: the in-box guard hook ran `n` checks (n >= 1). A signal only:
    /// the guest, and an agent with sudo, can forge it.
    GuardChecks {
        n: u32,
    },
    Exited {
        code: Option<i32>,
    },
}

impl<'de> Deserialize<'de> for Event {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(d)?;
        no_extra_keys(&v, &["started", "activity", "turn_finished"]).map_err(D::Error::custom)?;
        let e = EventDef::deserialize(v).map_err(D::Error::custom)?;
        if e == (Event::GuardChecks { n: 0 }) {
            return Err(D::Error::custom("guard_checks n must be at least 1"));
        }
        Ok(e)
    }
}

/// Host answer to a hello.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostReply {
    Welcome { proto: String },
    Refuse { why: String },
}

/// Host to guest, on the control port.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Request {
    Setup(Setup),
    Type { text: String, enter: bool },
    Resize { rows: u16, cols: u16 },
    Poweroff,
    Export { n: u32 },
    Advance { n: u32, paths: Option<Vec<String>> },
}

#[derive(Deserialize)]
#[serde(
    remote = "Request",
    tag = "t",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum RequestDef {
    Setup(Setup),
    Type { text: String, enter: bool },
    Resize { rows: u16, cols: u16 },
    Poweroff,
    Export { n: u32 },
    Advance { n: u32, paths: Option<Vec<String>> },
}

impl<'de> Deserialize<'de> for Request {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(d)?;
        no_extra_keys(&v, &["poweroff"]).map_err(D::Error::custom)?;
        RequestDef::deserialize(v).map_err(D::Error::custom)
    }
}

/// Guest answer to a request.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Reply {
    Ok,
    Err { why: String },
}

#[derive(Deserialize)]
#[serde(
    remote = "Reply",
    tag = "t",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum ReplyDef {
    Ok,
    Err { why: String },
}

impl<'de> Deserialize<'de> for Reply {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(d)?;
        no_extra_keys(&v, &["ok"]).map_err(D::Error::custom)?;
        ReplyDef::deserialize(v).map_err(D::Error::custom)
    }
}

/// Everything the guest needs to start the agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Setup {
    pub agent: AgentSpec,
    pub env: Vec<(String, String)>,
    pub files: Vec<SetupFile>,
    pub rows: u16,
    pub cols: u16,
}

/// The agent process to run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSpec {
    pub command: Vec<String>,
    pub user: String,
    pub cwd: String,
}

/// A file the guest writes before starting the agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupFile {
    pub path: String,
    pub mode: u32,
    pub text: String,
    /// Leave the file alone when its target exists in any form (a file, a
    /// link, a directory): a seed the agent may have changed since. Absent
    /// in older frames, so false there.
    #[serde(default)]
    pub keep_existing: bool,
}

/// The most environment variables a setup carries.
pub const MAX_ENV: usize = 64;
/// The most files a setup carries.
pub const MAX_FILES: usize = 64;
/// The most bytes of one setup file's text.
pub const MAX_FILE_TEXT: usize = 256 * 1024;
const FILE_ROOTS: [&str; 2] = ["/home/agent/", "/etc/saiife-guest/"];
/// Where the agent may run: the repo, or (Gemini CLI, plan 42 R9/R11) its
/// baked root-owned home with the repo as an include directory.
pub const AGENT_CWDS: [&str; 2] = ["/work", "/opt/saiife-gemini-home"];

fn env_name_ok(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_uppercase() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
}

fn path_ok(p: &str) -> bool {
    if p.contains('\0') {
        return false;
    }
    FILE_ROOTS.iter().any(|root| {
        p.strip_prefix(root).is_some_and(|rest| {
            rest.split('/')
                .all(|c| !c.is_empty() && c != "." && c != "..")
        })
    })
}

impl Setup {
    /// Validates the setup. The guest is the last line of defence, so it runs this too.
    pub fn check(&self) -> Result<(), String> {
        if self.agent.command.is_empty() {
            return Err("agent command is empty".into());
        }
        if self.agent.command.iter().any(|c| c.contains('\0')) {
            return Err("agent command contains NUL".into());
        }
        if self.agent.user != "agent" {
            return Err("agent user must be agent".into());
        }
        if !AGENT_CWDS.contains(&self.agent.cwd.as_str()) {
            return Err("agent cwd must be /work or /opt/saiife-gemini-home".into());
        }
        if self.env.len() > MAX_ENV {
            return Err(format!("more than {MAX_ENV} environment variables"));
        }
        for (k, v) in &self.env {
            if !env_name_ok(k) {
                return Err("bad environment variable name".into());
            }
            // COORD-7: the agent's env is an allowlist; the host may add
            // only an agent's model variables (no loader, shell or git
            // variable can ride in).
            if !crate::launch::is_model_var(k) {
                return Err(format!(
                    "environment variable {k} is not an agent model variable"
                ));
            }
            if v.contains('\0') || v.contains('\n') {
                return Err(format!("environment variable {k} has NUL or newline"));
            }
        }
        if self.files.len() > MAX_FILES {
            return Err(format!("more than {MAX_FILES} files"));
        }
        for f in &self.files {
            if !path_ok(&f.path) {
                return Err(format!("file path {:?} is not allowed", f.path));
            }
            // Bits, not magnitude: no setuid/setgid/sticky, no group/other write.
            if f.mode & !0o755 != 0 {
                return Err(format!("file mode {:o} is too wide", f.mode));
            }
            if f.path.starts_with("/etc/saiife-guest/") && f.mode != 0o644 && f.mode != 0o755 {
                return Err(format!(
                    "file mode {:o} must be 644 or 755 under /etc/saiife-guest",
                    f.mode
                ));
            }
            if f.text.len() > MAX_FILE_TEXT {
                return Err(format!("file {:?} is larger than 256 KiB", f.path));
            }
            if f.text.contains('\0') {
                return Err(format!("file {:?} contains NUL", f.path));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn pin<T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug>(
        v: T,
        j: Value,
    ) {
        assert_eq!(serde_json::to_value(&v).unwrap(), j);
        assert_eq!(serde_json::from_value::<T>(j).unwrap(), v);
    }

    fn setup() -> Setup {
        Setup {
            agent: AgentSpec {
                command: vec!["claude".into()],
                user: "agent".into(),
                cwd: "/work".into(),
            },
            env: vec![("OPENAI_API_KEY".into(), "b".into())],
            files: vec![SetupFile {
                path: "/home/agent/x".into(),
                mode: 0o644,
                text: "hi".into(),
                keep_existing: false,
            }],
            rows: 40,
            cols: 120,
        }
    }

    /// An older frame without the field still parses, as false.
    #[test]
    fn setup_file_keep_existing_defaults_to_false() {
        let f: SetupFile =
            serde_json::from_str(r#"{"path":"/home/agent/x","mode":420,"text":"hi"}"#).unwrap();
        assert!(!f.keep_existing);
        let f = SetupFile {
            keep_existing: true,
            ..f
        };
        let back: SetupFile = serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
        assert!(back.keep_existing);
    }

    #[test]
    fn msg_json_shapes_are_pinned() {
        pin(
            Event::Hello {
                proto: "saiife-guest/1".into(),
                guest: "0.1".into(),
                uptime_ms: 5,
                set_up: false,
            },
            json!({"t":"hello","proto":"saiife-guest/1","guest":"0.1","uptime_ms":5,"set_up":false}),
        );
        pin(Event::Started, json!({"t":"started"}));
        pin(Event::Activity, json!({"t":"activity"}));
        pin(Event::TurnFinished, json!({"t":"turn_finished"}));
        pin(
            Event::GuardChecks { n: 2 },
            json!({"t":"guard_checks","n":2}),
        );
        pin(
            Event::Exited { code: Some(1) },
            json!({"t":"exited","code":1}),
        );
        pin(
            Event::Exited { code: None },
            json!({"t":"exited","code":null}),
        );
        pin(
            HostReply::Welcome { proto: "p".into() },
            json!({"t":"welcome","proto":"p"}),
        );
        pin(
            HostReply::Refuse { why: "w".into() },
            json!({"t":"refuse","why":"w"}),
        );
        pin(Reply::Ok, json!({"t":"ok"}));
        pin(Reply::Err { why: "w".into() }, json!({"t":"err","why":"w"}));
        pin(
            Request::Setup(setup()),
            json!({"t":"setup","agent":{"command":["claude"],"user":"agent","cwd":"/work"},
                   "env":[["OPENAI_API_KEY","b"]],"files":[{"path":"/home/agent/x","mode":420,"text":"hi","keep_existing":false}],
                   "rows":40,"cols":120}),
        );
        pin(
            Request::Type {
                text: "x".into(),
                enter: true,
            },
            json!({"t":"type","text":"x","enter":true}),
        );
        pin(
            Request::Resize { rows: 1, cols: 2 },
            json!({"t":"resize","rows":1,"cols":2}),
        );
        pin(Request::Poweroff, json!({"t":"poweroff"}));
        pin(Request::Export { n: 3 }, json!({"t":"export","n":3}));
        pin(
            Request::Advance {
                n: 3,
                paths: Some(vec!["a".into()]),
            },
            json!({"t":"advance","n":3,"paths":["a"]}),
        );
        pin(
            Request::Advance { n: 3, paths: None },
            json!({"t":"advance","n":3,"paths":null}),
        );
    }

    /// FU1: a guard_checks event counts at least one check.
    #[test]
    fn guard_checks_zero_is_refused() {
        assert!(serde_json::from_value::<Event>(json!({"t":"guard_checks","n":0})).is_err());
        assert!(serde_json::from_value::<Event>(json!({"t":"guard_checks"})).is_err());
        assert!(serde_json::from_value::<Event>(json!({"t":"guard_checks","n":-1})).is_err());
        assert_eq!(
            serde_json::from_value::<Event>(json!({"t":"guard_checks","n":1})).unwrap(),
            Event::GuardChecks { n: 1 }
        );
    }

    #[test]
    fn unknown_field_is_refused() {
        // every variant, with an extra key, must be refused by its own enum
        let e = |t: &str, extra: Value| {
            let mut v = extra;
            v["t"] = json!(t);
            v["zzz"] = json!(1);
            v
        };
        assert!(serde_json::from_value::<Event>(e("started", json!({}))).is_err());
        assert!(serde_json::from_value::<Event>(e("activity", json!({}))).is_err());
        assert!(serde_json::from_value::<Event>(e("turn_finished", json!({}))).is_err());
        assert!(serde_json::from_value::<Event>(e("exited", json!({"code":1}))).is_err());
        assert!(serde_json::from_value::<Event>(e("guard_checks", json!({"n":1}))).is_err());
        assert!(serde_json::from_value::<Event>(e(
            "hello",
            json!({"proto":"p","guest":"g","uptime_ms":1,"set_up":true})
        ))
        .is_err());
        assert!(serde_json::from_value::<HostReply>(e("welcome", json!({"proto":"p"}))).is_err());
        assert!(serde_json::from_value::<HostReply>(e("refuse", json!({"why":"p"}))).is_err());
        assert!(serde_json::from_value::<Reply>(e("ok", json!({}))).is_err());
        assert!(serde_json::from_value::<Reply>(e("err", json!({"why":"p"}))).is_err());
        assert!(serde_json::from_value::<Request>(e("poweroff", json!({}))).is_err());
        assert!(
            serde_json::from_value::<Request>(e("type", json!({"text":"","enter":false}))).is_err()
        );
        assert!(
            serde_json::from_value::<Request>(e("resize", json!({"rows":1,"cols":1}))).is_err()
        );
        assert!(serde_json::from_value::<Request>(e("export", json!({"n":1}))).is_err());
        assert!(
            serde_json::from_value::<Request>(e("advance", json!({"n":1,"paths":null}))).is_err()
        );
        // Setup newtype variant: unknown key at the top and in the nested structs
        let mut s = serde_json::to_value(Request::Setup(setup())).unwrap();
        assert!(serde_json::from_value::<Request>(s.clone()).is_ok());
        let mut top = s.clone();
        top["zzz"] = json!(1);
        assert!(serde_json::from_value::<Request>(top).is_err());
        s["agent"]["zzz"] = json!(1);
        assert!(serde_json::from_value::<Request>(s.clone()).is_err());
        let mut f = serde_json::to_value(Request::Setup(setup())).unwrap();
        f["files"][0]["zzz"] = json!(1);
        assert!(serde_json::from_value::<Request>(f).is_err());
        // unknown tag
        assert!(serde_json::from_value::<Request>(json!({"t":"nope"})).is_err());
    }

    #[test]
    fn setup_check_rules() {
        assert_eq!(setup().check(), Ok(()));
        let bad = |f: &dyn Fn(&mut Setup)| {
            let mut s = setup();
            f(&mut s);
            assert!(s.check().is_err());
        };
        bad(&|s| s.agent.command.clear());
        bad(&|s| s.agent.command = vec!["a\0b".into()]);
        bad(&|s| s.agent.user = "root".into());
        bad(&|s| s.agent.cwd = "/tmp".into());
        for cwd in [
            "/",
            "/home",
            "/home/agent",
            "/home/agent/",
            "/home/agent/x",
            "/opt",
            "/opt/saiife-gemini-home/",
            "/opt/saiife-gemini-home/x",
            "/work/",
            "/work/x",
            "/etc",
        ] {
            bad(&|s| s.agent.cwd = cwd.into());
        }
        let mut home = setup();
        home.agent.cwd = "/opt/saiife-gemini-home".into();
        assert_eq!(home.check(), Ok(()));
        for n in ["a", "1A", "A-B", "", &"A".repeat(65)] {
            bad(&|s| s.env = vec![(n.into(), "v".into())]);
        }
        bad(&|s| s.env = vec![("OPENAI_API_KEY".into(), "a\nb".into())]);
        bad(&|s| s.env = vec![("OPENAI_API_KEY".into(), "a\0b".into())]);
        bad(&|s| {
            s.env = (0..65)
                .map(|_| ("OPENAI_API_KEY".to_string(), String::new()))
                .collect()
        });
        let mut s = setup();
        s.env = (0..64)
            .map(|_| ("OPENAI_API_KEY".to_string(), String::new()))
            .collect();
        assert_eq!(s.check(), Ok(()));
        // COORD-7: only an agent's model variables; every agent's are fine
        let mut s = setup();
        s.env = crate::launch::MODEL_ENV
            .iter()
            .flat_map(|(_, vars)| vars.iter())
            .map(|v| (v.to_string(), "v".to_string()))
            .collect();
        assert_eq!(s.check(), Ok(()));
        for n in [
            "_A9",
            "A",
            "FOO",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "BASH_ENV",
            "ENV",
            "NODE_OPTIONS",
            "PROMPT_COMMAND",
            "PYTHONPATH",
            "PATH",
            "HOME",
            "SHELL",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_KEY_0",
            "GIT_CONFIG_GLOBAL",
            "GIT_EXTERNAL_DIFF",
            "GIT_SSH_COMMAND",
            "GIT_TEMPLATE_DIR",
            "SSH_SK_PROVIDER",
            "HTTPS_PROXY",
        ] {
            let mut s = setup();
            s.env.push((n.into(), "v".into()));
            assert_eq!(
                s.check(),
                Err(format!(
                    "environment variable {n} is not an agent model variable"
                )),
                "{n}"
            );
        }
        for p in [
            "rel/x",
            "/etc/passwd",
            "/home/agent",
            "/home/agentx/y",
            "/home/agent/../x",
            "/home/agent/./x",
            "/home/agent//x",
            "/home/agent/x\0",
            "/etc/saiife-guest/../x",
            "/home/agent/",
        ] {
            bad(&|s| s.files[0].path = p.into());
        }
        let mut s = setup();
        s.files[0].path = "/etc/saiife-guest/a.json".into();
        s.files[0].mode = 0o755;
        assert_eq!(s.check(), Ok(()));
        bad(&|s| s.files[0].mode = 0o756);
        // modes are checked by bits, not magnitude (home files)
        for m in [
            0o722, 0o733, 0o707, 0o757, 0o666, 0o4555, 0o2755, 0o1755, 0o4755,
        ] {
            bad(&|s| s.files[0].mode = m);
        }
        for m in [0o644, 0o755, 0o600, 0o700, 0o400] {
            let mut s = setup();
            s.files[0].mode = m;
            assert_eq!(s.check(), Ok(()), "{m:o}");
        }
        // /etc/saiife-guest files are exactly 0644 or 0755
        for m in [0o600, 0o700, 0o400, 0o640, 0o722] {
            let mut s = setup();
            s.files[0].path = "/etc/saiife-guest/a.json".into();
            s.files[0].mode = m;
            assert!(s.check().is_err(), "{m:o}");
        }
        let mut s = setup();
        s.files[0].path = "/etc/saiife-guest/a.json".into();
        s.files[0].mode = 0o644;
        assert_eq!(s.check(), Ok(()));
        bad(&|s| s.files[0].text = "a\0".into());
        bad(&|s| s.files[0].text = "x".repeat(256 * 1024 + 1));
        let mut s = setup();
        s.files[0].text = "x".repeat(256 * 1024);
        assert_eq!(s.check(), Ok(()));
        bad(&|s| {
            s.files = (0..65)
                .map(|i| SetupFile {
                    path: format!("/home/agent/f{i}"),
                    mode: 0o600,
                    text: String::new(),
                    keep_existing: false,
                })
                .collect()
        });
    }
}
