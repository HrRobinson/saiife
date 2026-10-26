//! `saiife connect <service>`: the admin's one-step setup of a connector
//! service (spec §6.8.3, §8.1). It stores the secret through the daemon
//! (the `secret add` flow) and writes `<config dir>/policy.d/<service>.toml`
//! with every operation listed but commented out, so the service starts
//! deny-all. Linux only. Exit codes as `saiife secret`.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;

#[derive(Args)]
pub struct ConnectArgs {
    /// The service's name (a-z, 0-9, `_`, `-`); also the default connector,
    /// secret name and the policy file name.
    pub service: String,
    /// The connector manifest id (default: the service name).
    #[arg(long, value_name = "ID")]
    pub connector: Option<String>,
    /// The secret's name (default: the service name).
    #[arg(long, value_name = "NAME")]
    pub secret: Option<String>,
    /// A manifest parameter, `k=v` (repeatable). A missing required one is
    /// asked for on a terminal.
    #[arg(long = "param", value_name = "K=V")]
    pub params: Vec<String>,
    /// Read the secret value from this file.
    #[arg(long, value_name = "PATH", conflicts_with = "from_env")]
    pub from_file: Option<PathBuf>,
    /// Read the secret value from this environment variable.
    #[arg(long, value_name = "VAR")]
    pub from_env: Option<String>,
    /// The system config (default /etc/saiife/config.toml).
    #[arg(long = "config", visible_alias = "system-config", value_name = "FILE")]
    pub config: Option<PathBuf>,
}

#[cfg(not(target_os = "linux"))]
pub fn run(_args: ConnectArgs) -> ExitCode {
    eprintln!("saiife: locked mode needs Linux in this version (macOS: v2.1)");
    ExitCode::from(5)
}

#[cfg(target_os = "linux")]
pub fn run(args: ConnectArgs) -> ExitCode {
    use crate::secret_cmd::linux::Stop;
    match linux::go(args) {
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

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;
    use std::io::BufRead;
    use std::os::fd::AsFd;
    use std::path::{Path, PathBuf};

    use saiife_broker::manifest::{builtin, load_local, Manifest, OpKind, HTTP_CONNECTOR};

    use super::ConnectArgs;
    use crate::secret_cmd::linux::{add_secret, source, Stop};

    const SYSTEM_CONFIG: &str = "/etc/saiife/config.toml";

    fn refuse<T>(m: impl Into<String>) -> Result<T, Stop> {
        Err(Stop::Refused(m.into()))
    }

    pub(super) fn go(a: ConnectArgs) -> Result<(), Stop> {
        let config = a.config.unwrap_or_else(|| PathBuf::from(SYSTEM_CONFIG));
        let service = a.service;
        if !valid_name(&service) {
            return refuse("service names use a-z, 0-9, `_` and `-` (up to 64 characters)");
        }
        let connector = a.connector.unwrap_or_else(|| service.clone());
        let secret = a.secret.unwrap_or_else(|| service.clone());
        let conf_dir = config.parent().unwrap_or_else(|| Path::new("."));

        // 1. The manifest.
        if connector == HTTP_CONNECTOR {
            return refuse("the http connector is configured by hand: see docs/connectors/http.md");
        }
        let manifest = find_manifest(&connector, conf_dir)?;

        // 2. The parameters.
        let params = collect_params(&manifest, &a.params)?;

        // 3. The target must be free and writable, before anything is stored.
        let dir = conf_dir.join("policy.d");
        let target = dir.join(format!("{service}.toml"));
        if std::fs::symlink_metadata(&target).is_ok() {
            return refuse(format!("policy.d/{service}.toml exists; edit it"));
        }
        check_writable(&dir)?;
        let text = render(&service, &secret, &manifest, &params);

        // 4. The secret, through the daemon (admin check included).
        add_secret(
            &config,
            &secret,
            secret_kind(&manifest),
            std::slice::from_ref(&service),
            source(a.from_file, a.from_env),
        )?;

        // 5. The policy file. If it fails, tell how to undo the secret.
        let wrote = std::fs::create_dir_all(&dir)
            .and_then(|()| saiife_system::fsops::write_new_file(&target, text.as_bytes(), 0o644));
        if let Err(e) = wrote {
            return refuse(format!(
                "cannot write {}: {e}\nthe secret was stored; undo it with: saiife secret remove {secret}",
                target.display()
            ));
        }
        outln!("added {secret}");
        outln!("next: edit {}, then saiife policy reload", target.display());
        Ok(())
    }

    fn valid_name(s: &str) -> bool {
        !s.is_empty()
            && s.len() <= 64
            && s.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    }

    fn find_manifest(id: &str, conf_dir: &Path) -> Result<Manifest, Stop> {
        if let Some(m) = builtin().iter().find(|m| m.id == id) {
            return Ok(m.clone());
        }
        let local = load_local(&conf_dir.join("connectors"))
            .map_err(|e| Stop::Refused(format!("cannot load local connectors: {e}")))?;
        local
            .into_iter()
            .find(|m| m.id == id)
            .ok_or_else(|| Stop::Refused(format!("unknown connector {id}")))
    }

    /// The secret kind the manifest's auth needs.
    fn secret_kind(m: &Manifest) -> &'static str {
        match m.auth.first() {
            Some(a) if a.kind == "basic" => "basic",
            Some(a) if a.secret_field == "value" => "header",
            _ => "token",
        }
    }

    fn collect_params(m: &Manifest, given: &[String]) -> Result<BTreeMap<String, String>, Stop> {
        let mut out = BTreeMap::new();
        for kv in given {
            let Some((k, v)) = kv.split_once('=') else {
                return refuse(format!("--param {kv:?}: expected k=v"));
            };
            if !m.params.contains_key(k) {
                return refuse(format!("{} has no parameter {k}", m.id));
            }
            if out.insert(k.to_string(), v.to_string()).is_some() {
                return refuse(format!("--param {k} given twice"));
            }
        }
        let tty = rustix::termios::isatty(std::io::stdin().as_fd());
        for (name, spec) in &m.params {
            if spec.required && !out.contains_key(name) {
                if !tty {
                    return refuse(format!("missing --param {name}"));
                }
                eprint!("{name}: ");
                let mut line = String::new();
                std::io::stdin()
                    .lock()
                    .read_line(&mut line)
                    .map_err(|e| Stop::Refused(format!("cannot read the terminal: {e}")))?;
                let v = line.trim_end_matches(['\n', '\r']).to_string();
                if v.is_empty() {
                    return refuse(format!("missing --param {name}"));
                }
                out.insert(name.clone(), v);
            }
        }
        for (name, v) in &out {
            let ty = m.params[name]
                .param_type()
                .map_err(|e| Stop::Refused(format!("connector {}: {e}", m.id)))?;
            ty.check(v)
                .map_err(|why| Stop::Refused(format!("--param {name}: {why}")))?;
        }
        Ok(out)
    }

    fn q(s: &str) -> String {
        toml::Value::String(s.to_string()).to_string()
    }

    /// The policy file: an active service table, every operation commented.
    fn render(
        service: &str,
        secret: &str,
        m: &Manifest,
        params: &BTreeMap<String, String>,
    ) -> String {
        let mut s = format!(
            "# Written by `saiife connect {service}`. The service starts deny-all: every\n\
             # operation of {} is listed below, commented out. Move the lines you\n\
             # want into allow, ask or deny, uncomment the array, then run\n\
             # `saiife policy reload`. Deny beats ask beats allow.\n\n\
             [services.{service}]\nconnector = {}\nsecret = {}\n\n",
            m.id,
            q(&m.id),
            q(secret)
        );
        for list in ["allow", "ask", "deny"] {
            s.push_str(&format!("# {list} = [\n"));
            for o in &m.operation {
                let mark = match o.kind {
                    OpKind::Read => "",
                    OpKind::Write => " write",
                    OpKind::Delete => " delete",
                    OpKind::Bulk => " bulk",
                };
                let qual = o
                    .qualifier
                    .as_deref()
                    .map(|q| format!(" (qualifier {q})"))
                    .unwrap_or_default();
                s.push_str(&format!(
                    "#   {}, # {}{mark}{qual}\n",
                    q(&o.capability),
                    o.id
                ));
            }
            s.push_str("# ]\n\n");
        }
        s.push_str(&format!("[services.{service}.params]\n"));
        for (k, v) in params {
            s.push_str(&format!("{k} = {}\n", q(v)));
        }
        s
    }

    /// `policy.d` (or, when it is missing, its parent) must be writable.
    fn check_writable(dir: &Path) -> Result<(), Stop> {
        let probe = if dir.is_dir() {
            dir
        } else {
            dir.parent().unwrap_or_else(|| Path::new("."))
        };
        rustix::fs::access(probe, rustix::fs::Access::WRITE_OK)
            .map_err(|e| Stop::Refused(format!("cannot write to {}: {e}", probe.display())))
    }
}
