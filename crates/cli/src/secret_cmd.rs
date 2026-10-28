//! `saiife secret add|list|rotate|remove`: the admin's way into the vault
//! (spec §8.7), through the daemon. Linux only. Exit codes: 0 ok, 2
//! refused, 5 the daemon cannot be reached. A value comes from a file, an
//! environment variable or a terminal prompt without echo; it is never
//! printed and never part of an error message.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Subcommand;

#[derive(Subcommand)]
pub enum SecretAction {
    /// Store a new secret. The value is read from --from-file, --from-env
    /// or, on a terminal, a prompt without echo.
    Add {
        /// The secret's name: a-z, 0-9, `.`, `_`, `-`; up to 64 characters.
        name: String,
        /// token, basic, header, oauth2, aws, gcp_sa or azure_sp.
        #[arg(long, value_name = "KIND")]
        kind: String,
        /// A service allowed to use it (repeatable, at least one).
        #[arg(long = "service", value_name = "SERVICE", required = true)]
        services: Vec<String>,
        /// Read the value from this file (basic: `username:password`;
        /// oauth2: a JSON object with client_id, client_secret and
        /// refresh_token; aws, azure_sp: a JSON object with the kind's
        /// fields; gcp_sa: Google's service account key file).
        #[arg(long, value_name = "PATH", conflicts_with = "from_env")]
        from_file: Option<PathBuf>,
        /// Read the value from this environment variable (kinds with one
        /// value only).
        #[arg(long, value_name = "VAR")]
        from_env: Option<String>,
    },
    /// List the secrets: names and metadata, never values.
    List {
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Replace the value of a secret (its kind and services stay).
    Rotate {
        name: String,
        #[arg(long, value_name = "PATH", conflicts_with = "from_env")]
        from_file: Option<PathBuf>,
        #[arg(long, value_name = "VAR")]
        from_env: Option<String>,
    },
    /// Delete a secret.
    Remove { name: String },
    /// Move plaintext credentials from an agent user's home and projects
    /// into the vault (the daemon keeps a backup of each changed file for
    /// 7 days), then remove them from the file.
    Import {
        /// The agent user whose files are scanned.
        #[arg(long, value_name = "NAME")]
        user: String,
        /// A project root to scan for `.env*` files (repeatable).
        #[arg(long = "project", value_name = "DIR")]
        projects: Vec<PathBuf>,
        /// Answer yes for every credential in this file (repeatable).
        #[arg(long = "yes-to", value_name = "PATH")]
        yes_to: Vec<PathBuf>,
        /// The service the credentials in this file are for, as
        /// `<path>=<service>` (repeatable): a configured service or a
        /// built-in connector.
        #[arg(long = "service", value_name = "PATH=SERVICE")]
        services: Vec<String>,
        /// The user's home (default: from /etc/passwd). Test seam, debug
        /// builds only.
        #[cfg(debug_assertions)]
        #[arg(long, hide = true, value_name = "DIR")]
        home: Option<PathBuf>,
    },
}

#[cfg(not(target_os = "linux"))]
pub fn run(_config: Option<PathBuf>, _action: SecretAction) -> ExitCode {
    eprintln!("saiife: locked mode needs Linux in this version (macOS: v2.1)");
    ExitCode::from(5)
}

#[cfg(target_os = "linux")]
pub fn run(config: Option<PathBuf>, action: SecretAction) -> ExitCode {
    linux::run(config, action)
}

#[cfg(target_os = "linux")]
pub(crate) mod linux {
    use super::SecretAction;
    use serde_json::{json, Map, Value};
    use std::collections::BTreeMap;
    use std::io::Read;
    use std::os::fd::AsFd;
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;
    use std::time::{Duration, Instant};
    use zeroize::Zeroizing;

    use saiife_ipc::client::ClientError;

    use crate::broker::{self, Target};

    /// `secret import` in personal broker mode (plan 16, decision 6).
    const PERSONAL_IMPORT: &str = "personal broker: use secret add";
    /// The longest value read from a file, a variable or a terminal.
    const MAX_VALUE_BYTES: usize = 64 * 1024;
    const MIN_VALUE_BYTES: usize = 4;
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
    const CALL_TIMEOUT: Duration = Duration::from_secs(10);

    /// Why the command stops: `Refused` is exit 2, `Unavailable` exit 5.
    pub(crate) enum Stop {
        Refused(String),
        /// The daemon said `forbidden` (also exit 2).
        Forbidden(String),
        Unavailable(String),
        /// `saiife run`: the command is not on `PATH` (exit 127).
        NotFound(String),
        /// The daemon made the change but could not record it (exit 2).
        Unrecorded(String),
    }

    type Fields = BTreeMap<&'static str, Zeroizing<String>>;

    pub(crate) enum Source {
        File(PathBuf),
        Env(String),
        Terminal,
    }

    pub(crate) fn source(file: Option<PathBuf>, env: Option<String>) -> Source {
        match (file, env) {
            (Some(f), _) => Source::File(f),
            (None, Some(v)) => Source::Env(v),
            (None, None) => Source::Terminal,
        }
    }

    pub fn run(config: Option<PathBuf>, action: SecretAction) -> ExitCode {
        match target(config.as_deref()).and_then(|t| go(&t, action)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(Stop::Refused(m) | Stop::Forbidden(m) | Stop::Unrecorded(m)) => {
                eprintln!("saiife: {m}");
                ExitCode::from(2)
            }
            Err(Stop::Unavailable(m)) => {
                eprintln!("saiife: {m}");
                ExitCode::from(5)
            }
            Err(Stop::NotFound(m)) => {
                eprintln!("saiife: {m}");
                ExitCode::from(127)
            }
        }
    }

    /// The daemon this command talks to (the resolver, decision 10): a
    /// flag or a locked `/etc/saiife/config.toml` is the locked daemon,
    /// else the personal broker.
    pub(crate) fn target(flag: Option<&Path>) -> Result<Target, Stop> {
        broker::resolve_here(flag).map_err(Stop::Unavailable)
    }

    fn go(config: &Target, action: SecretAction) -> Result<(), Stop> {
        match action {
            SecretAction::List { json } => {
                let a = call_to(config, "secret.list", Map::new())?;
                let secrets = a.get("secrets").cloned().unwrap_or(json!([]));
                if json {
                    outln!("{}", json!({ "secrets": secrets }));
                } else {
                    print_table(&secrets);
                }
                Ok(())
            }
            SecretAction::Import {
                user,
                projects,
                yes_to,
                services,
                #[cfg(debug_assertions)]
                home,
            } => {
                #[cfg(not(debug_assertions))]
                let home = None;
                // Import moves plaintext out of the agent's reach; the
                // personal broker cannot (the same uid reads the key).
                if !config.is_locked() {
                    let _ = (user, projects, yes_to, services, home);
                    return Err(Stop::Refused(PERSONAL_IMPORT.into()));
                }
                crate::import_cmd::run(
                    config.config(),
                    crate::import_cmd::ImportArgs {
                        user,
                        projects,
                        yes_to,
                        services,
                        home,
                    },
                )
            }
            SecretAction::Remove { name } => {
                call_to(config, "secret.remove", args([("name", json!(name))]))?;
                outln!("removed {name}");
                Ok(())
            }
            SecretAction::Add {
                name,
                kind,
                services,
                from_file,
                from_env,
            } => {
                add_secret(config, &name, &kind, &services, source(from_file, from_env))?;
                outln!("added {name}");
                Ok(())
            }
            SecretAction::Rotate {
                name,
                from_file,
                from_env,
            } => {
                // The stored kind says which fields to read.
                let l = match call_to(config, "secret.list", Map::new()) {
                    Ok(l) => l,
                    // Not an admin: let the daemon refuse and record the
                    // rotate itself (no value is read or sent).
                    Err(Stop::Forbidden(_)) => {
                        return call_to(config, "secret.rotate", args([("name", json!(name))]))
                            .map(|_| ());
                    }
                    Err(e) => return Err(e),
                };
                let kind = l["secrets"]
                    .as_array()
                    .and_then(|a| a.iter().find(|s| s["name"] == json!(name)))
                    .and_then(|s| s["kind"].as_str())
                    .map(str::to_string)
                    .ok_or_else(|| Stop::Refused(format!("no secret named {name}")))?;
                let fields = gather(&kind, source(from_file, from_env))?;
                call_to(
                    config,
                    "secret.rotate",
                    args([("name", json!(name)), ("fields", fields_json(&fields))]),
                )?;
                outln!("rotated {name}");
                Ok(())
            }
        }
    }

    /// The Task 5 add flow: check the kind, read the value (file, variable or
    /// terminal) and send `secret.add`. Shared with `saiife connect`.
    pub(crate) fn add_secret(
        config: &Target,
        name: &str,
        kind: &str,
        services: &[String],
        src: Source,
    ) -> Result<(), Stop> {
        check_kind(kind)?;
        let fields = gather(kind, src)?;
        call_to(
            config,
            "secret.add",
            args([
                ("name", json!(name)),
                ("kind", json!(kind)),
                ("fields", fields_json(&fields)),
                ("allowed_services", json!(services)),
            ]),
        )?;
        Ok(())
    }

    fn args<const N: usize>(kv: [(&str, Value); N]) -> Map<String, Value> {
        kv.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    fn fields_json(f: &Fields) -> Value {
        let mut m = Map::new();
        for (k, v) in f {
            m.insert((*k).to_string(), Value::String(v.to_string()));
        }
        Value::Object(m)
    }

    fn check_kind(kind: &str) -> Result<(), Stop> {
        match kind {
            "token" | "basic" | "header" | "oauth2" | "aws" | "gcp_sa" | "azure_sp" => Ok(()),
            _ => Err(Stop::Refused(
                "unknown kind (token, basic, header, oauth2, aws, gcp_sa or azure_sp)".into(),
            )),
        }
    }

    /// One call on a fresh connection to the locked daemon of `config`
    /// (a flag: `saiife lockdown`, `secret import`).
    pub(crate) fn call(
        config: &Path,
        op: &str,
        a: Map<String, Value>,
    ) -> Result<Map<String, Value>, Stop> {
        call_to(&target(Some(config))?, op, a)
    }

    /// One call on a fresh connection to `t`.
    pub(crate) fn call_to(
        t: &Target,
        op: &str,
        a: Map<String, Value>,
    ) -> Result<Map<String, Value>, Stop> {
        let down = |e: &ClientError| Stop::Unavailable(broker::unreachable(t, e));
        let mut c = broker::connect(t, Instant::now() + CONNECT_TIMEOUT).map_err(|e| down(&e))?;
        c.call(op, a, Instant::now() + CALL_TIMEOUT)
            .map_err(|e| match e {
                ClientError::Refused { code, message } if code == "forbidden" => {
                    Stop::Forbidden(message)
                }
                ClientError::Refused { code, message } if code == "unrecorded" => {
                    Stop::Unrecorded(message)
                }
                ClientError::Refused { message, .. } => Stop::Refused(message),
                other => down(&other),
            })
    }

    fn print_table(secrets: &Value) {
        let rows: Vec<[String; 4]> = secrets
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|s| {
                        let services = s["allowed_services"]
                            .as_array()
                            .map(|v| {
                                v.iter()
                                    .filter_map(Value::as_str)
                                    .collect::<Vec<_>>()
                                    .join(",")
                            })
                            .unwrap_or_default();
                        [
                            s["name"].as_str().unwrap_or("").to_string(),
                            s["kind"].as_str().unwrap_or("").to_string(),
                            services,
                            s["last_used"].as_str().unwrap_or("never").to_string(),
                        ]
                    })
                    .collect()
            })
            .unwrap_or_default();
        if rows.is_empty() {
            outln!("no secrets");
            return;
        }
        let head = ["NAME", "KIND", "SERVICES", "LAST USED"].map(String::from);
        let mut w = [0usize; 4];
        for r in std::iter::once(&head).chain(rows.iter()) {
            for (i, c) in r.iter().enumerate() {
                w[i] = w[i].max(c.chars().count());
            }
        }
        for r in std::iter::once(&head).chain(rows.iter()) {
            outln!(
                "{:<w0$}  {:<w1$}  {:<w2$}  {}",
                r[0],
                r[1],
                r[2],
                r[3],
                w0 = w[0],
                w1 = w[1],
                w2 = w[2]
            );
        }
    }

    // ---- reading the value ----

    /// The fields of `kind` from `src`.
    fn gather(kind: &str, src: Source) -> Result<Fields, Stop> {
        let mut f = Fields::new();
        match src {
            Source::Terminal => {
                if !rustix::termios::isatty(std::io::stdin().as_fd()) {
                    return Err(Stop::Refused(
                        "saiife secret needs a terminal to read the value; use --from-file or --from-env"
                            .into(),
                    ));
                }
                match kind {
                    "basic" => {
                        f.insert("username", prompt("username: ")?);
                        f.insert("password", prompt("password: ")?);
                    }
                    "header" => {
                        f.insert("value", prompt("value: ")?);
                    }
                    // Paste flow (decision 8): the client id is not a
                    // secret; the client secret and refresh token are read
                    // without echo.
                    "oauth2" => {
                        f.insert("client_id", prompt_echo("client_id: ")?);
                        f.insert("client_secret", prompt("client_secret: ")?);
                        f.insert("refresh_token", prompt("refresh_token: ")?);
                    }
                    "aws" => {
                        f.insert("access_key_id", prompt_echo("access_key_id: ")?);
                        f.insert("secret_access_key", prompt("secret_access_key: ")?);
                        if let Some(t) = prompt_optional("session_token (empty for none): ")? {
                            f.insert("session_token", t);
                        }
                    }
                    "gcp_sa" => {
                        f.insert("client_email", prompt_echo("client_email: ")?);
                        f.insert("private_key_id", prompt("private_key_id: ")?);
                        // One line: a pasted key has its line breaks as `\n`.
                        let k = prompt("private_key (one line, line breaks as \\n): ")?;
                        f.insert("private_key", Zeroizing::new(k.replace("\\n", "\n")));
                        if let Some(p) = prompt_optional("project_id (empty for none): ")? {
                            f.insert("project_id", p);
                        }
                    }
                    "azure_sp" => {
                        f.insert("tenant_id", prompt_echo("tenant_id: ")?);
                        f.insert("client_id", prompt_echo("client_id: ")?);
                        f.insert("client_secret", prompt("client_secret: ")?);
                    }
                    _ => {
                        f.insert("token", prompt("token: ")?);
                    }
                }
            }
            Source::File(p) => {
                let mut raw = read_file(&p)?;
                strip_eol(&mut raw);
                single(kind, utf8(&raw)?, &mut f)?;
            }
            Source::Env(var) => {
                if matches!(kind, "aws" | "gcp_sa" | "azure_sp") {
                    return Err(Stop::Refused(format!(
                        "a {kind} secret has several fields; use --from-file or the terminal, not --from-env"
                    )));
                }
                let mut v = std::env::var_os(&var)
                    .ok_or_else(|| Stop::Refused(format!("environment variable {var} is not set")))?
                    .into_string()
                    .map_err(|_| Stop::Refused("the value is not UTF-8 text".into()))?;
                if v.len() > MAX_VALUE_BYTES {
                    return Err(Stop::Refused("secret value is too long".into()));
                }
                if v.ends_with('\n') {
                    v.pop();
                    if v.ends_with('\r') {
                        v.pop();
                    }
                }
                single(kind, Zeroizing::new(v), &mut f)?;
            }
        }
        for (k, v) in &f {
            let min = if matches!(
                *k,
                "username"
                    | "client_id"
                    | "tenant_id"
                    | "client_email"
                    | "project_id"
                    | "access_key_id"
            ) {
                1
            } else {
                MIN_VALUE_BYTES
            };
            if v.len() < min {
                return Err(Stop::Refused("secret value is too short".into()));
            }
        }
        Ok(f)
    }

    /// One text value into the fields of `kind` (basic: split at the first `:`).
    fn single(kind: &str, v: Zeroizing<String>, f: &mut Fields) -> Result<(), Stop> {
        match kind {
            "basic" => {
                let Some((u, p)) = v.split_once(':') else {
                    return Err(Stop::Refused(
                        "a basic secret takes username:password".into(),
                    ));
                };
                f.insert("username", Zeroizing::new(u.to_string()));
                f.insert("password", Zeroizing::new(p.to_string()));
            }
            "header" => {
                f.insert("value", v);
            }
            "oauth2" => oauth2_fields(&v, f)?,
            "aws" => json_fields(
                &v,
                f,
                &["access_key_id", "secret_access_key"],
                &["session_token"],
                &[],
            )?,
            "azure_sp" => json_fields(
                &v,
                f,
                &["tenant_id", "client_id", "client_secret"],
                &[],
                &[],
            )?,
            "gcp_sa" => gcp_fields(&v, f)?,
            _ => {
                f.insert("token", v);
            }
        }
        Ok(())
    }

    /// An oauth2 secret from a file or a variable: one JSON object with
    /// exactly `client_id`, `client_secret` and `refresh_token` (strings).
    /// An error never quotes the input.
    fn oauth2_fields(v: &str, f: &mut Fields) -> Result<(), Stop> {
        const KEYS: [&str; 3] = ["client_id", "client_secret", "refresh_token"];
        let shape = || {
            Stop::Refused(
                "an oauth2 secret takes a JSON object with client_id, client_secret and refresh_token"
                    .into(),
            )
        };
        // A duplicate key is refused: `{"refresh_token":"a","refresh_token":"b"}`
        // would otherwise keep one of the two silently.
        let o = match saiife_broker::pipeline::strict_json(v.as_bytes()) {
            Some(Value::Object(o)) => o,
            _ => return Err(shape()),
        };
        if o.len() != KEYS.len() {
            return Err(shape());
        }
        for k in KEYS {
            let s = o.get(k).and_then(Value::as_str).ok_or_else(shape)?;
            f.insert(k, Zeroizing::new(s.to_string()));
        }
        Ok(())
    }

    /// A cloud secret from a JSON object: every `required` key, any of the
    /// `optional` ones, nothing else except the `ignored` names. An error
    /// never quotes the input.
    fn json_fields(
        v: &str,
        f: &mut Fields,
        required: &[&'static str],
        optional: &[&'static str],
        ignored: &[&str],
    ) -> Result<(), Stop> {
        let shape = || {
            Stop::Refused(format!(
                "this secret takes a JSON object with the fields {}{}",
                required.join(", "),
                if optional.is_empty() {
                    String::new()
                } else {
                    format!(" (optional: {})", optional.join(", "))
                }
            ))
        };
        let o = match saiife_broker::pipeline::strict_json(v.as_bytes()) {
            Some(Value::Object(o)) => o,
            _ => return Err(shape()),
        };
        let known =
            |k: &str| required.contains(&k) || optional.contains(&k) || ignored.contains(&k);
        if !o.keys().all(|k| known(k)) {
            return Err(shape());
        }
        for k in required.iter().chain(optional) {
            match o.get(*k) {
                Some(Value::String(s)) if !s.is_empty() => {
                    f.insert(k, Zeroizing::new(s.clone()));
                }
                Some(_) => return Err(shape()),
                None if required.contains(k) => return Err(shape()),
                None => {}
            }
        }
        Ok(())
    }

    /// A GCP service account: the fields by name, or Google's key file
    /// (`"type": "service_account"`). A key file's `token_uri` is ignored:
    /// the token endpoint is fixed in the daemon.
    fn gcp_fields(v: &str, f: &mut Fields) -> Result<(), Stop> {
        const FILE_ONLY: [&str; 7] = [
            "type",
            "client_id",
            "auth_uri",
            "auth_provider_x509_cert_url",
            "client_x509_cert_url",
            "universe_domain",
            "token_uri",
        ];
        let required = ["client_email", "private_key", "private_key_id"];
        let optional = ["project_id"];
        let mut ignored: &[&str] = &[];
        if let Some(Value::Object(o)) = saiife_broker::pipeline::strict_json(v.as_bytes()) {
            if let Some(t) = o.get("type") {
                if t.as_str() != Some("service_account") {
                    return Err(Stop::Refused(
                        "this key file is not a service account key (type must be service_account)"
                            .into(),
                    ));
                }
                if o.contains_key("token_uri") {
                    outln!("note: token_uri is ignored; the token endpoint is fixed");
                }
                ignored = &FILE_ONLY;
            }
        }
        json_fields(v, f, &required, &optional, ignored)
    }

    /// Exactly one trailing `\n` or `\r\n` goes; nothing else.
    fn strip_eol(b: &mut Vec<u8>) {
        if b.last() == Some(&b'\n') {
            b.pop();
            if b.last() == Some(&b'\r') {
                b.pop();
            }
        }
    }

    fn utf8(b: &[u8]) -> Result<Zeroizing<String>, Stop> {
        std::str::from_utf8(b)
            .map(|s| Zeroizing::new(s.to_string()))
            .map_err(|_| Stop::Refused("the value is not UTF-8 text".into()))
    }

    fn read_file(p: &Path) -> Result<Zeroizing<Vec<u8>>, Stop> {
        let cannot = |e: std::io::Error| Stop::Refused(format!("cannot read {}: {e}", p.display()));
        let f = std::fs::File::open(p).map_err(cannot)?;
        let mut buf = Zeroizing::new(Vec::new());
        f.take(MAX_VALUE_BYTES as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(cannot)?;
        if buf.len() > MAX_VALUE_BYTES {
            return Err(Stop::Refused("secret value is too long".into()));
        }
        Ok(buf)
    }

    /// Puts the terminal back as it was, on every path out (return, error,
    /// panic). Ctrl-C does not need a signal handler: `ISIG` is off while
    /// the prompt is up, so it arrives as a byte and ends the prompt here.
    struct Restore {
        orig: rustix::termios::Termios,
    }

    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = rustix::termios::tcsetattr(
                std::io::stdin().as_fd(),
                rustix::termios::OptionalActions::Flush,
                &self.orig,
            );
        }
    }

    /// One line from the terminal without echo.
    fn prompt(label: &str) -> Result<Zeroizing<String>, Stop> {
        use rustix::termios::{InputModes, LocalModes, OptionalActions, SpecialCodeIndex};
        let stdin = std::io::stdin();
        let fd = stdin.as_fd();
        let tty = |e: rustix::io::Errno| Stop::Refused(format!("cannot read the terminal: {e}"));
        let orig = rustix::termios::tcgetattr(fd).map_err(tty)?;
        let mut raw = orig.clone();
        raw.local_modes &= !(LocalModes::ECHO | LocalModes::ICANON | LocalModes::ISIG);
        raw.input_modes &= !InputModes::IXON;
        raw.special_codes[SpecialCodeIndex::VMIN] = 1;
        raw.special_codes[SpecialCodeIndex::VTIME] = 0;
        let _restore = Restore { orig };
        rustix::termios::tcsetattr(fd, OptionalActions::Flush, &raw).map_err(tty)?;
        eprint!("{label}");
        let r = read_line(fd);
        eprintln!();
        match r {
            Ok(b) => utf8(&b),
            Err(e) => Err(e),
        }
    }

    /// A prompt that may be left empty.
    fn prompt_optional(label: &str) -> Result<Option<Zeroizing<String>>, Stop> {
        match prompt(label) {
            Ok(v) => Ok(Some(v)),
            Err(Stop::Refused(m)) if m == "no value read" => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// One line from the terminal, echoed (a value that is not a secret).
    fn prompt_echo(label: &str) -> Result<Zeroizing<String>, Stop> {
        eprint!("{label}");
        let mut line = Zeroizing::new(String::new());
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| Stop::Refused(format!("cannot read the terminal: {e}")))?;
        let v = line.trim_end_matches(['\r', '\n']);
        if v.is_empty() {
            return Err(Stop::Refused("no value read".into()));
        }
        if v.len() > MAX_VALUE_BYTES {
            return Err(Stop::Refused("secret value is too long".into()));
        }
        Ok(Zeroizing::new(v.to_string()))
    }

    fn read_line(fd: std::os::fd::BorrowedFd<'_>) -> Result<Zeroizing<Vec<u8>>, Stop> {
        let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
        let mut b = [0u8; 1];
        loop {
            match rustix::io::read(fd, &mut b) {
                Ok(0) => break,
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => return Err(Stop::Refused(format!("cannot read the terminal: {e}"))),
            }
            match b[0] {
                // Ctrl-C: stop here; `Restore` puts the terminal back.
                0x03 => return Err(Stop::Refused("interrupted".into())),
                b'\n' | b'\r' => break,
                // Ctrl-D ends the value, or aborts when nothing was typed.
                0x04 => {
                    if buf.is_empty() {
                        return Err(Stop::Refused("no value read".into()));
                    }
                    break;
                }
                0x7f | 0x08 => {
                    // Drop the last character, whole (UTF-8).
                    while buf.last().is_some_and(|c| c & 0xC0 == 0x80) {
                        buf.pop();
                    }
                    buf.pop();
                }
                c if c < 0x20 => {}
                c => {
                    if buf.len() >= MAX_VALUE_BYTES {
                        return Err(Stop::Refused("secret value is too long".into()));
                    }
                    buf.push(c);
                }
            }
        }
        if buf.is_empty() {
            return Err(Stop::Refused("no value read".into()));
        }
        Ok(buf)
    }

    #[cfg(test)]
    mod tests {
        use super::{gcp_fields, json_fields, strip_eol, Fields, Stop};

        fn key_file(extra: &str) -> String {
            let pem = concat!(
                "-----BEGIN ",
                "PRIVATE KEY-----\\nTESTBODYTESTBODY0001\\n-----END ",
                "PRIVATE KEY-----\\n"
            );
            format!(
                r#"{{"type":"service_account","project_id":"my-proj-1","private_key_id":"abcd1234","private_key":"{pem}","client_email":"sa@my-proj-1.iam.gserviceaccount.com","client_id":"1234","auth_uri":"https://accounts.example/auth","token_uri":"https://evil.example/token","universe_domain":"googleapis.com"{extra}}}"#
            )
        }

        fn msg(r: Result<(), Stop>) -> String {
            match r {
                Ok(()) => "ok".into(),
                Err(Stop::Refused(m)) => m,
                Err(_) => "other".into(),
            }
        }

        #[test]
        fn gcp_key_file_parsed_token_uri_ignored() {
            let mut f = Fields::new();
            assert_eq!(msg(gcp_fields(&key_file(""), &mut f)), "ok");
            let names: Vec<&str> = f.keys().copied().collect();
            assert_eq!(
                names,
                [
                    "client_email",
                    "private_key",
                    "private_key_id",
                    "project_id"
                ]
            );
            assert!(f["private_key"].contains("PRIVATE KEY-----\nTESTBODY"));
            // token_uri is not a field of the secret, and its value is nowhere.
            assert!(f.values().all(|v| !v.contains("evil.example")));
            // The plain field form works too, and an unknown key does not.
            let mut g = Fields::new();
            let plain = r#"{"client_email":"sa@p.iam.gserviceaccount.com","private_key":"k","private_key_id":"i"}"#;
            assert_eq!(msg(gcp_fields(plain, &mut g)), "ok");
            let mut h = Fields::new();
            let extra = plain.replace('}', r#","token_uri":"x"}"#);
            let m = msg(gcp_fields(&extra, &mut h));
            assert!(m.starts_with("this secret takes a JSON object"), "{m}");
        }

        #[test]
        fn gcp_wrong_type_refused() {
            for kind in ["authorized_user", "external_account", ""] {
                let text = key_file("").replace("service_account", kind);
                let mut f = Fields::new();
                let m = msg(gcp_fields(&text, &mut f));
                assert!(m.contains("not a service account key"), "{kind}: {m}");
                assert!(!m.contains("TESTBODY") && f.is_empty());
            }
            // A type that is not a string is refused too.
            let text = key_file("").replace(r#""type":"service_account""#, r#""type":1"#);
            let mut f = Fields::new();
            assert!(msg(gcp_fields(&text, &mut f)).contains("not a service account key"));
        }

        #[test]
        fn json_fields_refuse_without_quoting() {
            let secret = concat!("leaky-", "value-0001");
            let mut f = Fields::new();
            let text =
                format!(r#"{{"tenant_id":"t.example.com","client_id":"c","oops":"{secret}"}}"#);
            let m = msg(json_fields(
                &text,
                &mut f,
                &["tenant_id", "client_id", "client_secret"],
                &[],
                &[],
            ));
            assert!(m.contains("tenant_id, client_id, client_secret"), "{m}");
            assert!(!m.contains(secret));
        }

        #[test]
        fn strips_exactly_one_line_ending() {
            let mut cases: Vec<(&[u8], &[u8])> = vec![
                (b"abc\n", b"abc"),
                (b"abc\r\n", b"abc"),
                (b"abc\n\n", b"abc\n"),
                (b"abc\r", b"abc\r"),
                (b"abc", b"abc"),
            ];
            for (i, o) in cases.drain(..) {
                let mut v = i.to_vec();
                strip_eol(&mut v);
                assert_eq!(v, o);
            }
        }
    }
}
