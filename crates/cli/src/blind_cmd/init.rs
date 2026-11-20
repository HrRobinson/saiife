//! `saiife blind init` (plan 48 T6, R48-7, spec §5.1): six steps, Data,
//! Columns, Models, Cloud, Rules and Test, each with flags for scripts;
//! and `saiife blind data add`, which runs the Data and Columns steps
//! (the same code) and builds the dataset.
//!
//! - **Data** stages the source (`blind.data.stage`): a file is opened here
//!   and passed as a descriptor (R47-5); a Postgres source is local only
//!   (R-C8) and is read from policy, so its source is written to
//!   `policy.d/blind-<dataset>.toml` first.
//! - **Columns** shows the classifier's guesses that need the user, takes
//!   `public` marks only for columns that pass (never names, IDs or
//!   amounts), aliases, the entity tables, and the column that identifies
//!   the person in a table that has none (`public::NO_IDENTIFIER`).
//! - **Models** needs `[blind.ner]` pinned by sha256 (R-C8) and starts the
//!   fetch, then polls `blind.status` once a second (R-C6).
//! - **Cloud** needs an API key: a vault token secret allowing
//!   `blind-model` (R-C8: no subscription login).
//! - **Rules** writes `policy.d/blind.toml` (the `[blind]` globals) and
//!   `policy.d/blind-<dataset>.toml`, reloads the policy and builds the
//!   dataset (`blind.data.commit`).
//! - **Test** asks a question made from the schema, with the preview.
//!
//! A stop or a failure before the build puts every policy file it wrote
//! back as it was (and reloads when a reload had loaded them). In locked
//! mode the drop-in dir is root's: run it as root.

use clap::Args;
use std::path::PathBuf;

/// `key=value` (`--class`, `--alias`).
fn parse_kv(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((k, v)) if !k.trim().is_empty() && !v.trim().is_empty() => {
            Ok((k.trim().to_string(), v.trim().to_string()))
        }
        _ => Err(format!("{s:?} is not key=value")),
    }
}

/// The Data and Columns steps' flags (`init` and `data add`).
#[derive(Args)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct DataArgs {
    /// The dataset's name (a-z, 0-9 and -, up to 32).
    #[arg(long)]
    dataset: Option<String>,
    /// The source file: csv, xlsx or sqlite (opened here, passed to the
    /// daemon).
    #[arg(long)]
    file: Option<PathBuf>,
    /// A local Postgres: a unix socket dir, localhost, 127.0.0.1 or ::1.
    #[arg(long)]
    postgres_host: Option<String>,
    #[arg(long)]
    postgres_port: Option<u16>,
    #[arg(long)]
    postgres_db: Option<String>,
    #[arg(long)]
    postgres_user: Option<String>,
    /// The vault secret holding the database password.
    #[arg(long)]
    postgres_password_secret: Option<String>,
    /// A table to read (repeatable).
    #[arg(long)]
    postgres_tables: Vec<String>,
    /// Keep every guess of the classifier without asking.
    #[arg(long)]
    accept_guesses: bool,
    /// Columns to mark public (table.column, comma-separated); names, IDs
    /// and amounts are refused.
    #[arg(long, value_delimiter = ',')]
    public: Vec<String>,
    /// A column's class: table.column=identifier|quasi|sensitive|free_text|public.
    #[arg(long = "class", value_parser = parse_kv)]
    classes: Vec<(String, String)>,
    /// A name the cloud sees instead: table.column=alias or table=alias.
    #[arg(long = "alias", value_parser = parse_kv)]
    aliases: Vec<(String, String)>,
    /// An entity table: table:key:name_col[+name_col]:show_col[+…]:word:word_da.
    #[arg(long = "entity")]
    entities: Vec<String>,
    /// The column that identifies the person in a table: table:column.
    #[arg(long = "identifier")]
    identifiers: Vec<String>,
    /// Who may ask (a user name or group:<name>; repeatable).
    #[arg(long)]
    users: Vec<String>,
    /// Who may approve methods (repeatable).
    #[arg(long)]
    approvers: Vec<String>,
    /// The dataset's k (default: [blind] k, else 10).
    #[arg(long)]
    k: Option<u32>,
}

/// `saiife blind init`'s flags.
#[derive(Args)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct InitArgs {
    #[command(flatten)]
    data: DataArgs,
    /// The name detector's model file (https), pinned by --ner-model-sha256.
    #[arg(long)]
    ner_model_url: Option<String>,
    #[arg(long)]
    ner_model_sha256: Option<String>,
    #[arg(long)]
    ner_vocab_url: Option<String>,
    #[arg(long)]
    ner_vocab_sha256: Option<String>,
    #[arg(long)]
    ner_labels_url: Option<String>,
    #[arg(long)]
    ner_labels_sha256: Option<String>,
    /// The vault token secret (allowing blind-model) of the cloud planner.
    #[arg(long)]
    cloud_secret: Option<String>,
    /// The cloud planner's model (default claude-opus-5-5).
    #[arg(long)]
    model: Option<String>,
    /// Every ask of this dataset shows the method first (no --yes).
    #[arg(long)]
    preview_required: bool,
    /// Yes to the fetch and to running the test question.
    #[arg(long)]
    yes: bool,
    /// Print the request the test question sends to the planner.
    #[arg(long)]
    show_sent: bool,
    /// Leave out the test question.
    #[arg(long)]
    skip_test: bool,
}

#[cfg(target_os = "linux")]
pub(super) use imp::{data_add, init};

#[cfg(target_os = "linux")]
mod imp {
    use super::super::admin::{open_source, parse_class};
    use super::super::ask;
    use super::super::imp::{
        args, call, call_fds, ner_line, s, u, Stop, ASK_TIMEOUT, READ_TIMEOUT,
    };
    use super::super::{policy_file, Prompter};
    use super::{DataArgs, InitArgs};
    use crate::broker::Target;
    use crate::text::sanitize;
    use saiife_policy::blind::{
        BlindCfg, BlindDataset, BlindSource, CloudModelCfg, ColumnCfg, EntityCfg, NerCfg, TableCfg,
        COLUMN_CLASSES, DEFAULT_K,
    };
    use saiife_shield::public::{person_name_part, NO_IDENTIFIER};
    use saiife_shield::schema::{DatasetName, Lang};
    use serde_json::{json, Map, Value};
    use std::collections::{BTreeMap, BTreeSet};
    use std::os::fd::AsFd;
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;
    use std::time::Duration;

    /// R48-7: in locked mode the drop-in dir is root's.
    pub(crate) const NOT_ROOT_INIT: &str =
        "saiife blind init writes policy: run it as root (sudo saiife blind init)";
    const NOT_ROOT_ADD: &str =
        "saiife blind data add writes policy: run it as root (sudo saiife blind data add)";
    /// R-C8: no detector without a pin.
    pub(crate) const NO_PIN: &str = "no name detector is pinned yet: pass --ner-model-url and --ner-model-sha256 (and vocab, labels); see docs/data-shield.md";
    /// R-C8: Postgres is local only (the daemon's and the policy's text).
    pub(crate) const REMOTE_PG: &str = "remote Postgres needs TLS, which is a later stage";
    /// The vault service the planner's key must allow.
    const MODEL_SERVICE: &str = "blind-model";
    /// The secret name the Cloud step suggests when none is known.
    const DEFAULT_SECRET: &str = "anthropic";
    /// Under a step's head (`1/6 Data      `).
    const INDENT: &str = "              ";
    const POLL: Duration = Duration::from_secs(1);
    /// A fetch is polled for at most this many seconds.
    const MAX_POLLS: u32 = 6 * 3600;

    /// `n/of Name      ` (spec §5.1).
    fn head(n: usize, of: usize, name: &str) -> String {
        format!("{n}/{of} {name:<10}")
    }

    /// `label:` padded, then the text's lines (the rest under the first).
    fn labelled(label: &str, text: &str) -> Vec<String> {
        let pad = " ".repeat(17);
        text.split('\n')
            .enumerate()
            .map(|(i, l)| {
                let first = if i == 0 {
                    format!("{label:<17}")
                } else {
                    pad.clone()
                };
                format!("{INDENT}{first}{}", sanitize(l))
            })
            .collect()
    }

    fn euid_root() -> bool {
        rustix::process::geteuid().is_root()
    }

    // ----------------------------------------------------------- undo ----

    /// The policy files written so far, as they were before.
    #[derive(Default)]
    struct Undo {
        saved: Vec<policy_file::Previous>,
        /// A reload loaded something written here.
        loaded: bool,
    }

    impl Undo {
        /// Keeps `path` as it is now, once.
        fn save(&mut self, path: &Path) -> Result<(), Stop> {
            if !self.saved.iter().any(|p| p.path() == path) {
                self.saved
                    .push(policy_file::previous(path).map_err(Stop::Unavailable)?);
            }
            Ok(())
        }

        /// The build went live: what was written stays.
        fn keep(&mut self) {
            self.saved.clear();
            self.loaded = false;
        }

        /// Every saved file put back (or removed when it was new), then a
        /// reload when one had loaded them. What was done, when anything.
        fn undo(self, t: &Target) -> Option<String> {
            if self.saved.is_empty() {
                return None;
            }
            let mut bad = Vec::new();
            for p in self.saved.into_iter().rev() {
                let shown = sanitize(&p.path().display().to_string());
                if let Err(e) = p.restore(t) {
                    bad.push(format!("{shown} could not be put back: {}", sanitize(&e)));
                }
            }
            let mut note = if bad.is_empty() {
                "the policy files were put back as they were".to_string()
            } else {
                bad.join("; ")
            };
            if self.loaded {
                if let Err(why) = policy_file::reload(t) {
                    note.push_str(&format!(
                        "; the reload after that failed too: {}",
                        sanitize(&why)
                    ));
                }
            }
            Some(note)
        }
    }

    /// How a run ended.
    enum Outcome {
        Done,
        /// A step stopped (it said why): nothing written stays.
        Stopped,
        /// The dataset is set up; the test question did not answer.
        TestFailed,
    }

    fn finish(t: &Target, r: Result<Outcome, Stop>, undo: Undo) -> Result<ExitCode, Stop> {
        match r {
            Ok(Outcome::Done) => Ok(ExitCode::SUCCESS),
            Ok(Outcome::TestFailed) => Ok(ExitCode::from(2)),
            Ok(Outcome::Stopped) => {
                if let Some(n) = undo.undo(t) {
                    outln!("{INDENT}{n}");
                }
                Ok(ExitCode::from(2))
            }
            Err(e) => {
                let note = undo.undo(t);
                Err(match (e, note) {
                    (e, None) => e,
                    (Stop::Refused(m), Some(n)) => Stop::Refused(format!("{m}; {n}")),
                    (Stop::Unavailable(m), Some(n)) => Stop::Unavailable(format!("{m}; {n}")),
                })
            }
        }
    }

    // --------------------------------------------------------- policy ----

    /// The `[blind]` in force as this CLI reads it (config and drop-ins).
    /// When it does not load here (a broken drop-in), `config.toml`'s own
    /// `[blind]` and `policy.d/blind.toml`, with a warning: the reload
    /// will tell.
    fn policy_view(t: &Target, mine: &BlindCfg) -> BlindCfg {
        match saiife_policy::load_system(t.config()) {
            Ok(l) => l.config.blind,
            Err(e) => {
                if t.config().exists() {
                    crate::warn(&format!(
                        "the policy does not load here ({}); going on",
                        sanitize(&e.to_string())
                    ));
                }
                #[derive(serde::Deserialize)]
                struct Head {
                    #[serde(default)]
                    blind: BlindCfg,
                }
                let mut b = std::fs::read_to_string(t.config())
                    .ok()
                    .and_then(|x| toml::from_str::<Head>(&x).ok())
                    .map(|h| h.blind)
                    .unwrap_or_default();
                b.k = b.k.or(mine.k);
                b.ner = b.ner.take().or_else(|| mine.ner.clone());
                b.cloud = b.cloud.take().or_else(|| mine.cloud.clone());
                b
            }
        }
    }

    /// What `saiife blind` knows before it starts.
    struct Known {
        /// `[blind]` in force (all files).
        full: BlindCfg,
        /// `policy.d/blind.toml` (ours; what this run may rewrite).
        mine: BlindCfg,
        /// `mine` as it was read.
        mine0: BlindCfg,
    }

    fn known(t: &Target) -> Result<Known, Stop> {
        let mine = policy_file::read_globals(t).map_err(|e| Stop::Refused(sanitize(&e)))?;
        let full = policy_view(t, &mine);
        Ok(Known {
            full,
            mine0: mine.clone(),
            mine,
        })
    }

    // ------------------------------------------------------- the plan ----

    /// One staged column and the classifier's proposal.
    struct Col {
        table: String,
        name: String,
        ty: String,
        guess: String,
        uncertain: bool,
        refusal: Option<String>,
        /// (passing, total distinct) of a `public` mark.
        preview: Option<(u64, u64)>,
    }

    impl Col {
        fn key(&self) -> String {
            format!("{}.{}", self.table, self.name)
        }
    }

    /// What `blind.data.stage` answered.
    struct Staged {
        /// (table, rows band).
        tables: Vec<(String, String)>,
        cols: Vec<Col>,
    }

    impl Staged {
        fn parse(v: &Value) -> Staged {
            let mut tables = Vec::new();
            let mut cols = Vec::new();
            for t in v
                .get("tables")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let name = s(t, "name").to_string();
                tables.push((name.clone(), s(t, "rows_band").to_string()));
                for c in t
                    .get("columns")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    cols.push(Col {
                        table: name.clone(),
                        name: s(c, "name").to_string(),
                        ty: s(c, "type").to_string(),
                        guess: s(c, "guess").to_string(),
                        uncertain: c.get("uncertain").and_then(Value::as_bool) == Some(true),
                        refusal: c
                            .get("public_refusal")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        preview: c
                            .get("public_preview")
                            .map(|p| (u(p, "passing"), u(p, "total"))),
                    });
                }
            }
            Staged { tables, cols }
        }

        fn col(&self, key: &str) -> Option<&Col> {
            self.cols.iter().find(|c| c.key() == key)
        }

        fn has_table(&self, t: &str) -> bool {
            self.tables.iter().any(|(n, _)| n == t)
        }

        fn columns_of(&self, t: &str) -> Vec<&Col> {
            self.cols.iter().filter(|c| c.table == t).collect()
        }
    }

    /// The dataset as it will be written.
    struct Plan {
        name: String,
        source: BlindSource,
        classes: BTreeMap<String, String>,
        col_alias: BTreeMap<String, String>,
        table_alias: BTreeMap<String, String>,
        entities: Vec<EntityCfg>,
        users: Vec<String>,
        approvers: Vec<String>,
        k: Option<u32>,
        preview_required: bool,
        /// The dataset as policy defines it now (a re-run): what no flag
        /// changes stays (list_cap, joins, classes, aliases, entities).
        base: Option<BlindDataset>,
    }

    impl Plan {
        fn dataset(&self) -> BlindDataset {
            let columns = self
                .classes
                .iter()
                .map(|(k, c)| {
                    (
                        k.clone(),
                        ColumnCfg {
                            class: c.clone(),
                            alias: self.col_alias.get(k).cloned(),
                        },
                    )
                })
                .collect();
            let tables = self
                .table_alias
                .iter()
                .map(|(t, a)| {
                    (
                        t.clone(),
                        TableCfg {
                            alias: Some(a.clone()),
                        },
                    )
                })
                .collect();
            BlindDataset {
                name: self.name.clone(),
                source: self.source.clone(),
                users: self.users.clone(),
                approvers: self.approvers.clone(),
                mode: "exact".into(),
                k: self.k,
                preview_required: self.preview_required,
                list_cap: self.base.as_ref().and_then(|b| b.list_cap),
                tables,
                columns,
                entity: self.entities.clone(),
                joins: self
                    .base
                    .as_ref()
                    .map(|b| b.joins.clone())
                    .unwrap_or_default(),
            }
        }
    }

    /// An entity as `--entity` writes it.
    pub(crate) fn entity_spec(e: &EntityCfg) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}",
            e.table,
            e.key,
            e.names.join("+"),
            e.show.join("+"),
            e.word.clone().unwrap_or_default(),
            e.word_da.clone().unwrap_or_default()
        )
    }

    /// `table:key:name[+name]:show[+show]:word:word_da` (show, word and
    /// word_da may be empty or left out), its columns checked.
    fn parse_entity(spec: &str, st: &Staged) -> Result<EntityCfg, String> {
        let parts: Vec<&str> = spec.split(':').map(str::trim).collect();
        if parts.len() < 3 || parts.len() > 6 {
            return Err(format!(
                "{} is not table:key:name_col[+name_col]:show_col[+…]:word:word_da",
                sanitize(spec)
            ));
        }
        let list = |i: usize| -> Vec<String> {
            parts
                .get(i)
                .map(|p| {
                    p.split('+')
                        .map(str::trim)
                        .filter(|x| !x.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default()
        };
        let word = |i: usize| -> Option<String> {
            parts
                .get(i)
                .filter(|w| !w.is_empty())
                .map(|w| w.to_string())
        };
        let e = EntityCfg {
            table: parts[0].to_string(),
            key: parts[1].to_string(),
            names: list(2),
            show: list(3),
            word: word(4),
            word_da: word(5),
        };
        if !st.has_table(&e.table) {
            return Err(format!(
                "the entity table {} is not in the data",
                sanitize(&e.table)
            ));
        }
        if e.names.is_empty() {
            return Err(format!(
                "the entity {} needs at least one name column",
                sanitize(&e.table)
            ));
        }
        for c in std::iter::once(&e.key).chain(&e.names).chain(&e.show) {
            let key = format!("{}.{c}", e.table);
            if st.col(&key).is_none() {
                return Err(format!("{} is not a column of the data", sanitize(&key)));
            }
        }
        Ok(e)
    }

    /// `customers` -> `customer`.
    fn singular(t: &str) -> String {
        if let Some(x) = t.strip_suffix("ies") {
            format!("{x}y")
        } else if t.ends_with("ss") {
            t.to_string()
        } else if let Some(x) = t.strip_suffix('s') {
            x.to_string()
        } else {
            t.to_string()
        }
    }

    /// The entity tables the data suggests: a table with Identifier name
    /// columns (a person's name parts) and an INTEGER Identifier key (`id`
    /// or `<table>_id`); its quasi text columns are shown (never an
    /// Identifier one, R-C2).
    fn guess_entities(st: &Staged, classes: &BTreeMap<String, String>) -> Vec<EntityCfg> {
        let class = |c: &Col| classes.get(&c.key()).cloned().unwrap_or_default();
        let mut out = Vec::new();
        for (t, _) in &st.tables {
            let cols = st.columns_of(t);
            let names: Vec<String> = cols
                .iter()
                .filter(|c| c.ty == "text" && class(c) == "identifier" && person_name_part(&c.name))
                .map(|c| c.name.clone())
                .collect();
            let stem = singular(t);
            let key = cols.iter().find(|c| {
                c.ty == "integer"
                    && class(c) == "identifier"
                    && (c.name.eq_ignore_ascii_case("id")
                        || c.name.eq_ignore_ascii_case(&format!("{stem}_id")))
            });
            let (Some(key), false) = (key, names.is_empty()) else {
                continue;
            };
            let show = cols
                .iter()
                .filter(|c| c.ty == "text" && class(c) == "quasi")
                .map(|c| c.name.clone())
                .collect();
            out.push(EntityCfg {
                table: t.clone(),
                key: key.name.clone(),
                names,
                show,
                word: Some(stem),
                word_da: None,
            });
        }
        out
    }

    /// The test question (spec §5.1), from the first entity's words.
    pub(crate) fn test_question(lang: Lang, e: Option<&EntityCfg>, first_table: &str) -> String {
        match (lang, e) {
            (Lang::En, Some(e)) => {
                let w = e.word.clone().unwrap_or_else(|| singular(&e.table));
                format!("How many {} are there?", ask::plural(&w))
            }
            (Lang::Da, Some(e)) => {
                let w = e.word_da.clone().unwrap_or_else(|| e.table.clone());
                format!("Hvor mange {w} er der?")
            }
            (Lang::En, None) => format!("How many rows does {first_table} have?"),
            (Lang::Da, None) => format!("Hvor mange rækker har {first_table}?"),
        }
    }

    // ----------------------------------------------------- the checks ----

    /// The name the dataset gets: `--dataset`, else asked.
    fn dataset_name(a: &DataArgs, p: &mut dyn Prompter, cmd: &str) -> Result<String, Stop> {
        let name = match &a.dataset {
            Some(d) => d.clone(),
            None if p.is_interactive() => p
                .line("Name the dataset (a-z, 0-9 and -, for example crm): ")
                .map_err(Stop::Refused)?,
            None => {
                return Err(Stop::Refused(format!(
                    "{cmd} needs a dataset name: pass --dataset <name>"
                )))
            }
        };
        name.parse::<DatasetName>()
            .map_err(|e| Stop::Refused(sanitize(&e.to_string())))?;
        Ok(name)
    }

    /// The dataset may be (re)written here: not hand-written, not defined
    /// in another file.
    fn writable(t: &Target, ds: &str, k: &Known) -> Result<Option<BlindDataset>, Stop> {
        let mine = policy_file::read_dataset(t, ds).map_err(|e| Stop::Refused(sanitize(&e)))?;
        if mine.is_none() && k.full.dataset.iter().any(|d| d.name == ds) {
            let path = policy_file::dataset_path(t, ds).map_err(Stop::Refused)?;
            return Err(Stop::Refused(format!(
                "{} is defined in policy already, not in {} (the file saiife blind writes): change it where it is defined, or choose another name",
                sanitize(ds),
                sanitize(&path.display().to_string())
            )));
        }
        Ok(mine)
    }

    /// R-C8: a unix socket dir or the loopback host.
    pub(crate) fn local_pg(host: &str) -> bool {
        host.starts_with('/') || matches!(host, "localhost" | "127.0.0.1" | "::1")
    }

    // ------------------------------------------------------ 1/6 Data ----

    /// The kind of a source file, by its name.
    fn file_kind(f: &Path) -> Option<&'static str> {
        let ext = f.extension()?.to_str()?.to_ascii_lowercase();
        match ext.as_str() {
            "csv" => Some("csv"),
            "xlsx" => Some("xlsx"),
            "sqlite" | "sqlite3" | "db" => Some("sqlite"),
            _ => None,
        }
    }

    fn base_name(f: &Path) -> String {
        f.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("data")
            .to_string()
    }

    /// `2 tables (customers: about 100 rows, invoices: under 100 rows)`.
    fn tables_text(st: &Staged) -> String {
        let n = st.tables.len();
        let each: Vec<String> = st
            .tables
            .iter()
            .map(|(t, b)| {
                // `rows_band`: `<100` or `about 2 thousand`.
                let rows = match b.strip_prefix('<') {
                    Some(x) => format!("under {} rows", sanitize(x)),
                    None => format!("{} rows", sanitize(b)),
                };
                format!("{}: {rows}", sanitize(t))
            })
            .collect();
        let word = if n == 1 { "table" } else { "tables" };
        format!("{n} {word} ({})", each.join(", "))
    }

    /// Step 1: the source staged. A Postgres source is written to policy
    /// first (the daemon reads its settings there).
    fn data_step(
        t: &Target,
        a: &DataArgs,
        base: Option<&BlindDataset>,
        ds: &str,
        of: usize,
        p: &mut dyn Prompter,
        undo: &mut Undo,
    ) -> Result<(BlindSource, Staged), Stop> {
        let h = head(1, of, "Data");
        let (source, label, reply) = if let Some(host) = &a.postgres_host {
            if !local_pg(host) {
                return Err(Stop::Refused(REMOTE_PG.into()));
            }
            let need = |v: &Option<String>, flag: &str| -> Result<String, Stop> {
                v.clone()
                    .filter(|x| !x.is_empty())
                    .ok_or_else(|| Stop::Refused(format!("a Postgres source needs --{flag}")))
            };
            let dbname = need(&a.postgres_db, "postgres-db")?;
            let user = need(&a.postgres_user, "postgres-user")?;
            let secret = need(&a.postgres_password_secret, "postgres-password-secret")?;
            if a.postgres_tables.is_empty() {
                return Err(Stop::Refused(
                    "a Postgres source needs --postgres-tables (repeatable)".into(),
                ));
            }
            let source = BlindSource::Postgres {
                host: host.clone(),
                port: a.postgres_port,
                dbname: dbname.clone(),
                user,
                password_secret: secret,
                tables: a.postgres_tables.clone(),
            };
            // The source only, so the daemon can read it; Rules writes the
            // rest. A dataset in policy keeps everything else meanwhile.
            let first = match base {
                Some(b) => BlindDataset {
                    source: source.clone(),
                    ..b.clone()
                },
                None => BlindDataset {
                    name: ds.to_string(),
                    source: source.clone(),
                    users: a.users.clone(),
                    approvers: a.approvers.clone(),
                    mode: "exact".into(),
                    k: a.k,
                    preview_required: false,
                    list_cap: None,
                    tables: BTreeMap::new(),
                    columns: BTreeMap::new(),
                    entity: Vec::new(),
                    joins: Vec::new(),
                },
            };
            write_and_reload(t, None, &first, undo)?;
            let r = call(
                t,
                "blind.data.stage",
                args([("dataset", json!(ds)), ("kind", json!("postgres"))]),
                ASK_TIMEOUT,
            )?;
            let label = format!("postgres {} on {}", sanitize(&dbname), sanitize(host));
            (source, label, r)
        } else {
            let file = match &a.file {
                Some(f) => f.clone(),
                None if p.is_interactive() => {
                    let typed = p
                        .line("Which data? (a csv, xlsx or sqlite file): ")
                        .map_err(Stop::Refused)?;
                    if typed.is_empty() {
                        return Err(Stop::Refused("no file was given; nothing was done".into()));
                    }
                    PathBuf::from(typed)
                }
                None => {
                    return Err(Stop::Refused(
                        "which data? pass --file <path> (csv, xlsx or sqlite), or --postgres-host and the other --postgres flags".into(),
                    ))
                }
            };
            let shown = sanitize(&file.display().to_string());
            let kind = file_kind(&file).ok_or_else(|| {
                Stop::Refused(format!(
                    "{shown} is not a csv, xlsx or sqlite file (by its name)"
                ))
            })?;
            let name = base_name(&file);
            let opened = open_source(&file)?;
            let r = call_fds(
                t,
                "blind.data.stage",
                args([
                    ("dataset", json!(ds)),
                    ("kind", json!(kind)),
                    ("file_name", json!(name)),
                ]),
                &[opened.as_fd()],
                ASK_TIMEOUT,
            )?;
            drop(opened);
            let source = match kind {
                "csv" => BlindSource::Csv {
                    file_name: name.clone(),
                },
                "xlsx" => BlindSource::Xlsx {
                    file_name: name.clone(),
                },
                _ => BlindSource::Sqlite {
                    file_name: name.clone(),
                },
            };
            (source, sanitize(&name), r)
        };
        let st = Staged::parse(&Value::Object(reply));
        if st.tables.is_empty() {
            return Err(Stop::Refused(format!("{label} holds no table")));
        }
        outln!("{h}{label}  →  {}. Snapshot made.", tables_text(&st));
        Ok((source, st))
    }

    // --------------------------------------------------- 2/6 Columns ----

    /// The note of a `public` mark: `(<p> of <t> values pass k = <k>)`.
    fn pass_note(c: &Col, k: u32) -> String {
        match c.preview {
            Some((p, total)) => format!("({p} of {total} values pass k = {k})"),
            None => String::new(),
        }
    }

    /// Why `c` can never be public, or its note.
    fn check_public(c: &Col, k: u32) -> Result<String, String> {
        match c.refusal.as_deref() {
            Some(NO_IDENTIFIER) => Err(format!(
                "{} cannot be public yet: table {} {NO_IDENTIFIER}",
                sanitize(&c.key()),
                sanitize(&c.table)
            )),
            Some(why) => Err(format!(
                "{} cannot be public: it {}",
                sanitize(&c.key()),
                sanitize(why)
            )),
            None => Ok(pass_note(c, k)),
        }
    }

    /// Sets `key` to `class` (checked).
    fn set_class(
        st: &Staged,
        classes: &mut BTreeMap<String, String>,
        key: &str,
        class: &str,
        k: u32,
    ) -> Result<String, String> {
        let c = st
            .col(key)
            .ok_or_else(|| format!("{} is not a column of the data", sanitize(key)))?;
        if parse_class(class).is_none() {
            return Err(format!(
                "the class of {} must be one of: {}",
                sanitize(key),
                COLUMN_CLASSES.join(", ")
            ));
        }
        let note = if class == "public" {
            check_public(c, k)?
        } else {
            String::new()
        };
        classes.insert(key.to_string(), class.to_string());
        Ok(note)
    }

    /// A `table.column=alias` or `table=alias`.
    fn set_alias(st: &Staged, plan: &mut Plan, key: &str, alias: &str) -> Result<(), String> {
        if key.contains('.') {
            if st.col(key).is_none() {
                return Err(format!("{} is not a column of the data", sanitize(key)));
            }
            plan.col_alias.insert(key.to_string(), alias.to_string());
        } else {
            if !st.has_table(key) {
                return Err(format!("{} is not a table of the data", sanitize(key)));
            }
            plan.table_alias.insert(key.to_string(), alias.to_string());
        }
        Ok(())
    }

    /// The tables that hold personal data but no Identifier column
    /// (`NO_IDENTIFIER` in a proposal), under the classes chosen.
    fn without_identifier(st: &Staged, classes: &BTreeMap<String, String>) -> Vec<String> {
        let mut out = Vec::new();
        for (t, _) in &st.tables {
            let cols = st.columns_of(t);
            let flagged = cols
                .iter()
                .any(|c| c.refusal.as_deref() == Some(NO_IDENTIFIER));
            let has = cols
                .iter()
                .any(|c| classes.get(&c.key()).map(String::as_str) == Some("identifier"));
            if flagged && !has {
                out.push(t.clone());
            }
        }
        out
    }

    /// The question for a table without an identifying column.
    pub(crate) fn identifier_prompt(table: &str, cols: &[&str]) -> String {
        format!(
            "Which column identifies the person in {table}? ({}) ",
            cols.join(", ")
        )
    }

    /// The column that identifies the person in `table`: `--identifier`,
    /// else asked; refused for a script.
    fn ask_identifier(
        st: &Staged,
        table: &str,
        p: &mut dyn Prompter,
        classes: &mut BTreeMap<String, String>,
    ) -> Result<(), Stop> {
        let cols: Vec<String> = st
            .columns_of(table)
            .iter()
            .map(|c| sanitize(&c.name))
            .collect();
        let cols_ref: Vec<&str> = cols.iter().map(String::as_str).collect();
        let shown = sanitize(table);
        if !p.is_interactive() {
            return Err(Stop::Refused(format!(
                "table {shown} {NO_IDENTIFIER}. Which column identifies the person in {shown}? Pass --identifier {shown}:<column> (one of: {})",
                cols.join(", ")
            )));
        }
        for _ in 0..5 {
            let typed = p
                .line(&identifier_prompt(&shown, &cols_ref))
                .map_err(Stop::Refused)?;
            let key = format!("{table}.{typed}");
            if st.col(&key).is_some() {
                classes.insert(key, "identifier".into());
                return Ok(());
            }
            eprintln!("type one of: {}", cols.join(", "));
        }
        Err(Stop::Refused(format!(
            "no column of {shown} was chosen; nothing was written"
        )))
    }

    /// A y/N question (no on no answer).
    fn yes_no(p: &mut dyn Prompter, q: &str) -> bool {
        p.line(q).map(|l| ask::is_yes(&l)).unwrap_or(false)
    }

    /// Step 2: the classes, aliases, entities and identifying columns.
    #[allow(clippy::too_many_arguments)]
    fn columns_step(
        a: &DataArgs,
        st: &Staged,
        k: u32,
        of: usize,
        cmd: &str,
        p: &mut dyn Prompter,
        plan: &mut Plan,
    ) -> Result<(), Stop> {
        let refused = |m: String| Stop::Refused(m);
        // A re-run starts from the classes and aliases policy has now; a
        // column policy lists needs nobody again.
        let old = plan.base.clone();
        let old_cols = old.as_ref().map(|b| b.columns.clone()).unwrap_or_default();
        let mut classes: BTreeMap<String, String> = st
            .cols
            .iter()
            .map(|c| {
                let class = old_cols
                    .get(&c.key())
                    .map_or_else(|| c.guess.clone(), |x| x.class.clone());
                (c.key(), class)
            })
            .collect();
        for (key, c) in &old_cols {
            if let (Some(al), Some(_)) = (&c.alias, st.col(key)) {
                plan.col_alias.insert(key.clone(), al.clone());
            }
        }
        for (tb, c) in old.iter().flat_map(|b| b.tables.iter()) {
            if let (Some(al), true) = (&c.alias, st.has_table(tb)) {
                plan.table_alias.insert(tb.clone(), al.clone());
            }
        }
        let mut by_flag: BTreeSet<String> = old_cols.keys().cloned().collect();
        for (key, class) in &a.classes {
            set_class(st, &mut classes, key, class, k).map_err(refused)?;
            by_flag.insert(key.clone());
        }
        for key in a.public.iter().map(|x| x.trim()).filter(|x| !x.is_empty()) {
            set_class(st, &mut classes, key, "public", k).map_err(refused)?;
            by_flag.insert(key.to_string());
        }
        for spec in &a.identifiers {
            let (tb, c) = spec.split_once(':').ok_or_else(|| {
                Stop::Refused(format!(
                    "{} is not table:column (--identifier)",
                    sanitize(spec)
                ))
            })?;
            set_class(st, &mut classes, &format!("{tb}.{c}"), "identifier", k).map_err(refused)?;
            by_flag.insert(format!("{tb}.{c}"));
        }
        for (key, alias) in &a.aliases {
            set_alias(st, plan, key, alias).map_err(refused)?;
        }
        let need: Vec<&Col> = st
            .cols
            .iter()
            .filter(|c| c.uncertain && !by_flag.contains(&c.key()))
            .collect();
        let asks = p.is_interactive() && !a.accept_guesses;
        if !need.is_empty() && !asks && !a.accept_guesses {
            return Err(Stop::Refused(format!(
                "{} columns need you: run {cmd} in a terminal, or pass --accept-guesses (or --class table.column=class)",
                need.len()
            )));
        }
        let h = head(2, of, "Columns");
        if need.is_empty() {
            outln!("{h}{} columns classified. None need you.", st.cols.len());
        } else {
            outln!(
                "{h}{} columns classified. {} need you:",
                st.cols.len(),
                need.len()
            );
        }
        let w = need
            .iter()
            .map(|c| c.key().chars().count())
            .max()
            .unwrap_or(0);
        for c in &need {
            let key = sanitize(&c.key());
            let g = sanitize(&c.guess);
            let mut line = format!("{INDENT}{key:<w$}  looks like: {g}?  [{g}]");
            if c.guess == "public" {
                let n = pass_note(c, k);
                if !n.is_empty() {
                    line.push_str(&format!("   {n}"));
                }
            }
            if !asks {
                outln!("{line}");
                continue;
            }
            // Enter keeps the guess; a class sets it.
            for _ in 0..5 {
                let typed = p.line(&format!("{line} ")).unwrap_or_default();
                if typed.is_empty() {
                    break;
                }
                match set_class(st, &mut classes, &c.key(), &typed, k) {
                    Ok(note) => {
                        if !note.is_empty() {
                            eprintln!("{INDENT}{note}");
                        }
                        break;
                    }
                    Err(e) => eprintln!(
                        "{e} (Enter keeps [{g}]; one of: {})",
                        COLUMN_CLASSES.join(", ")
                    ),
                }
            }
        }
        if asks {
            if yes_no(p, "Mark more columns public? (y/N) ") {
                loop {
                    let typed = p
                        .line("Columns to make public (table.column, comma-separated; Enter when done): ")
                        .unwrap_or_default();
                    if typed.is_empty() {
                        break;
                    }
                    for key in typed.split(',').map(str::trim).filter(|x| !x.is_empty()) {
                        match set_class(st, &mut classes, key, "public", k) {
                            Ok(note) => eprintln!("{INDENT}{} is public {note}", sanitize(key)),
                            Err(e) => eprintln!("{INDENT}{e}"),
                        }
                    }
                }
            }
            if yes_no(p, "Alias column names for the cloud? (y/N) ") {
                loop {
                    let typed = p
                        .line("Aliases (table.column=alias or table=alias, comma-separated; Enter when done): ")
                        .unwrap_or_default();
                    if typed.is_empty() {
                        break;
                    }
                    for kv in typed.split(',').map(str::trim).filter(|x| !x.is_empty()) {
                        let r = super::parse_kv(kv)
                            .and_then(|(key, al)| set_alias(st, plan, &key, &al));
                        if let Err(e) = r {
                            eprintln!("{INDENT}{}", sanitize(&e));
                        }
                    }
                }
            }
        }
        // The entity tables: the flags, else the ones policy has now, else
        // the guess (confirmed or edited).
        let old_entities = old.as_ref().map(|b| b.entity.clone()).unwrap_or_default();
        if !a.entities.is_empty() {
            for spec in &a.entities {
                plan.entities.push(parse_entity(spec, st).map_err(refused)?);
            }
        } else if !old_entities.is_empty() {
            for e in old_entities {
                outln!("{INDENT}entity  {}  (kept)", sanitize(&entity_spec(&e)));
                plan.entities.push(e);
            }
        } else {
            for e in guess_entities(st, &classes) {
                let spec = entity_spec(&e);
                if !asks {
                    outln!("{INDENT}entity  {}", sanitize(&spec));
                    plan.entities.push(e);
                    continue;
                }
                let q = format!(
                    "{INDENT}entity  {}  Enter keeps it, - leaves it out, or type table:key:names:show:word:word_da: ",
                    sanitize(&spec)
                );
                let mut chosen = Some(e);
                for _ in 0..5 {
                    let typed = p.line(&q).unwrap_or_default();
                    if typed.is_empty() {
                        break;
                    }
                    if typed == "-" {
                        chosen = None;
                        break;
                    }
                    match parse_entity(&typed, st) {
                        Ok(x) => {
                            chosen = Some(x);
                            break;
                        }
                        Err(m) => eprintln!("{INDENT}{m}"),
                    }
                }
                plan.entities.extend(chosen);
            }
        }
        // A table with personal data and nothing that identifies the
        // person (plan 43 I4): which column does.
        for table in without_identifier(st, &classes) {
            ask_identifier(st, &table, p, &mut classes)?;
        }
        plan.classes = classes;
        Ok(())
    }

    // ---------------------------------------------------- 3/6 Models ----

    /// The `--ner-*` flags: all six, none, or refused.
    fn ner_flags(a: &InitArgs) -> Result<Option<NerCfg>, Stop> {
        let f = [
            ("--ner-model-url", &a.ner_model_url),
            ("--ner-model-sha256", &a.ner_model_sha256),
            ("--ner-vocab-url", &a.ner_vocab_url),
            ("--ner-vocab-sha256", &a.ner_vocab_sha256),
            ("--ner-labels-url", &a.ner_labels_url),
            ("--ner-labels-sha256", &a.ner_labels_sha256),
        ];
        let missing: Vec<&str> = f
            .iter()
            .filter(|(_, v)| v.is_none())
            .map(|(n, _)| *n)
            .collect();
        if missing.len() == f.len() {
            return Ok(None);
        }
        if !missing.is_empty() {
            return Err(Stop::Refused(format!(
                "the name detector is pinned by all three files and their sha256: pass {}",
                missing.join(", ")
            )));
        }
        let v = |o: &Option<String>| o.clone().unwrap_or_default();
        Ok(Some(NerCfg {
            model_url: v(&a.ner_model_url),
            model_sha256: v(&a.ner_model_sha256),
            vocab_url: v(&a.ner_vocab_url),
            vocab_sha256: v(&a.ner_vocab_sha256),
            labels_url: v(&a.ner_labels_url),
            labels_sha256: v(&a.ner_labels_sha256),
            max_bytes: None,
        }))
    }

    /// `ner-multi-onnx  sha256 41ab…7c`.
    pub(crate) fn pin_text(url: &str, sha: &str) -> String {
        let file = url
            .rsplit('/')
            .find(|x| !x.is_empty())
            .unwrap_or(url)
            .to_string();
        let short = if sha.len() >= 6 && sha.is_ascii() {
            format!("{}…{}", &sha[..4], &sha[sha.len() - 2..])
        } else {
            sha.to_string()
        };
        format!("{}  sha256 {}", sanitize(&file), sanitize(&short))
    }

    /// A `[blind]` singleton for this run: the flag's value, else the one
    /// in force. Set in another file than ours and different: refused.
    /// `Some` when ours must be (re)written with it.
    fn choose<T: Clone + PartialEq>(
        flag: Option<T>,
        full: &Option<T>,
        mine: &Option<T>,
        key: &str,
        flags: &str,
    ) -> Result<(Option<T>, bool), Stop> {
        let elsewhere = if mine.is_none() { full.clone() } else { None };
        match (flag, elsewhere) {
            (None, _) => Ok((full.clone(), false)),
            (Some(f), Some(e)) if f == e => Ok((Some(f), false)),
            (Some(_), Some(_)) => Err(Stop::Refused(format!(
                "[blind.{key}] is set in another policy file: change it there, or leave out {flags}"
            ))),
            (Some(f), None) => {
                let write = mine.as_ref() != Some(&f);
                Ok((Some(f), write))
            }
        }
    }

    /// `blind.status`'s `ner`.
    fn ner_state(t: &Target) -> Result<Value, Stop> {
        let v = Value::Object(call(t, "blind.status", Map::new(), READ_TIMEOUT)?);
        Ok(v.get("ner").cloned().unwrap_or(Value::Null))
    }

    /// Step 3: the pinned detector, its files fetched by the daemon.
    fn models_step(
        t: &Target,
        a: &InitArgs,
        k: &mut Known,
        p: &mut dyn Prompter,
        undo: &mut Undo,
    ) -> Result<bool, Stop> {
        let h = head(3, 6, "Models");
        let flag = ner_flags(a)?;
        let (ner, write) = choose(flag, &k.full.ner, &k.mine.ner, "ner", "the --ner flags")?;
        let Some(ner) = ner else {
            outln!("{h}{NO_PIN}");
            return Ok(false);
        };
        if write {
            k.mine.ner = Some(ner.clone());
            undo.save(&policy_file::globals_path(t))?;
            policy_file::write_globals(t, &k.mine).map_err(|e| Stop::Refused(sanitize(&e)))?;
            reload_or_stop(t, undo)?;
        }
        // The detector follows a reload in the background: a moment to
        // start (or to find its files missing).
        let mut n = ner_state(t)?;
        for _ in 0..50 {
            if s(&n, "state") != "not configured" {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
            n = ner_state(t)?;
        }
        let line = format!(
            "{h}name detector  {}  pinned.",
            pin_text(&ner.model_url, &ner.model_sha256)
        );
        if s(&n, "state") == "ready" {
            outln!("{line} Ready.");
            return Ok(true);
        }
        let fetch = if a.yes {
            outln!("{line} Fetching.");
            true
        } else if p.is_interactive() {
            outln!("{line}");
            p.line(&format!("{INDENT}Fetch? (Y/n) "))
                .map(|l| ask::is_run(&l))
                .unwrap_or(false)
        } else {
            return Err(Stop::Refused(
                "the name detector's files need fetching: pass --yes, or run saiife blind init in a terminal".into(),
            ));
        };
        if !fetch {
            outln!("{INDENT}Data Shield needs the name detector; nothing was set up");
            return Ok(false);
        }
        match call(t, "blind.ner.fetch", Map::new(), READ_TIMEOUT) {
            Ok(_) => {}
            // One runs already (busy): wait for it.
            Err(Stop::Refused(m)) if m.contains("being fetched already") => {}
            Err(e) => return Err(e),
        }
        let mut last = String::new();
        let mut idle = 0;
        for _ in 0..MAX_POLLS {
            std::thread::sleep(POLL);
            let n = ner_state(t)?;
            match s(&n, "state") {
                "ready" => {
                    outln!("{INDENT}{}", ner_line(&n));
                    return Ok(true);
                }
                "failed" => {
                    return Err(Stop::Unavailable(format!(
                        "the name detector could not be fetched: {}",
                        sanitize(s(&n, "reason"))
                    )))
                }
                "fetching" => {
                    let l = ner_line(&n);
                    if l != last {
                        eprintln!("{INDENT}{l}");
                        last = l;
                    }
                }
                _ => {
                    // The fetch is over but the detector did not start.
                    idle += 1;
                    if idle > 30 {
                        return Err(Stop::Unavailable(ner_line(&n)));
                    }
                }
            }
        }
        Err(Stop::Unavailable(
            "the name detector is still being fetched: see saiife blind status".into(),
        ))
    }

    // ----------------------------------------------------- 4/6 Cloud ----

    /// The vault's token secrets that allow `blind-model`.
    fn model_secrets(t: &Target) -> Result<Vec<String>, Stop> {
        let v = Value::Object(call(t, "secret.list", Map::new(), READ_TIMEOUT)?);
        Ok(v.get("secrets")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|x| {
                s(x, "kind") == "token"
                    && x.get("allowed_services")
                        .and_then(Value::as_array)
                        .is_some_and(|l| l.iter().any(|y| y.as_str() == Some(MODEL_SERVICE)))
            })
            .map(|x| s(x, "name").to_string())
            .collect())
    }

    /// Step 4: the planner's API key (R-C8: API keys only).
    fn cloud_step(t: &Target, a: &InitArgs, k: &mut Known) -> Result<bool, Stop> {
        let h = head(4, 6, "Cloud");
        let have = model_secrets(t)?;
        let named = a
            .cloud_secret
            .clone()
            .or_else(|| k.full.cloud.as_ref().map(|c| c.secret.clone()));
        let found = match &named {
            Some(n) => have.iter().any(|x| x == n).then(|| n.clone()),
            None => match have.as_slice() {
                [one] => Some(one.clone()),
                _ => None,
            },
        };
        let Some(secret) = found else {
            let name = named.unwrap_or_else(|| DEFAULT_SECRET.into());
            outln!(
                "{h}no API key for the planner in the vault: saiife secret add {} --kind token --service {MODEL_SERVICE}",
                sanitize(&name)
            );
            outln!("{INDENT}then run saiife blind init again (API keys only)");
            return Ok(false);
        };
        let model = a
            .model
            .clone()
            .or_else(|| k.full.cloud.as_ref().and_then(|c| c.model.clone()));
        let want = CloudModelCfg {
            secret: secret.clone(),
            model,
        };
        let flag = (a.cloud_secret.is_some() || a.model.is_some() || k.full.cloud.is_none())
            .then(|| want.clone());
        let (_, write) = choose(
            flag,
            &k.full.cloud,
            &k.mine.cloud,
            "cloud",
            "--cloud-secret and --model",
        )?;
        if write {
            k.mine.cloud = Some(want);
        }
        outln!("{h}Claude, API key in vault: {} ✓", sanitize(&secret));
        Ok(true)
    }

    // ----------------------------------------------------- 5/6 Rules ----

    /// `policy.reload`; when it fails, the stop with the loader's reason.
    fn reload_or_stop(t: &Target, undo: &mut Undo) -> Result<(), Stop> {
        match policy_file::reload(t) {
            Ok(()) => {
                undo.loaded = true;
                Ok(())
            }
            Err(why) => Err(Stop::Refused(format!(
                "the policy did not load, so nothing was set up: {}",
                sanitize(&why)
            ))),
        }
    }

    /// Writes `globals` (when given) and the dataset's file, then reloads.
    fn write_and_reload(
        t: &Target,
        globals: Option<&BlindCfg>,
        d: &BlindDataset,
        undo: &mut Undo,
    ) -> Result<(), Stop> {
        if let Some(g) = globals {
            undo.save(&policy_file::globals_path(t))?;
            policy_file::write_globals(t, g).map_err(|e| Stop::Refused(sanitize(&e)))?;
        }
        let path = policy_file::dataset_path(t, &d.name).map_err(Stop::Refused)?;
        undo.save(&path)?;
        policy_file::write_dataset(t, d).map_err(|e| Stop::Refused(sanitize(&e)))?;
        reload_or_stop(t, undo)
    }

    /// The table a commit refusal names as having no identifying column
    /// (`table <t> <NO_IDENTIFIER>`).
    pub(crate) fn no_identifier_table(m: &str) -> Option<String> {
        let rest = m.strip_prefix("table ")?;
        let t = rest.strip_suffix(NO_IDENTIFIER)?.strip_suffix(' ')?;
        (!t.is_empty() && !t.contains(' ')).then(|| t.to_string())
    }

    /// Writes the policy, reloads and builds (`blind.data.commit`); a
    /// table the build finds without an identifying column is asked for
    /// and the build tried again.
    fn build(
        t: &Target,
        plan: &mut Plan,
        globals: Option<&BlindCfg>,
        st: &Staged,
        p: &mut dyn Prompter,
        undo: &mut Undo,
    ) -> Result<(), Stop> {
        for _ in 0..=st.tables.len() {
            write_and_reload(t, globals, &plan.dataset(), undo)?;
            let r = call(
                t,
                "blind.data.commit",
                args([("dataset", json!(plan.name))]),
                ASK_TIMEOUT,
            );
            let table = match &r {
                Err(Stop::Refused(m)) => no_identifier_table(m),
                _ => None,
            };
            match (r, table) {
                (Ok(_), _) => {
                    undo.keep();
                    return Ok(());
                }
                (Err(_), Some(table)) => ask_identifier(st, &table, p, &mut plan.classes)?,
                (Err(e), None) => return Err(e),
            }
        }
        Err(Stop::Refused(
            "the build kept finding tables without an identifying column".into(),
        ))
    }

    /// Datasets other than `ds` that an older saiife built (manifest v1,
    /// no indexes) or that need a refresh: the command for each.
    fn refresh_hints(t: &Target, ds: &str) {
        let Ok(v) = call(t, "blind.status", Map::new(), READ_TIMEOUT) else {
            return;
        };
        for d in v
            .get("datasets")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let name = s(d, "name");
            if name == ds {
                continue;
            }
            let old = d
                .get("warnings")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .any(|w| w.ends_with(&format!("saiife blind data refresh --dataset {name}")));
            if old || s(d, "state") == "needs_refresh" {
                let n = sanitize(name);
                outln!("{INDENT}{n} needs a refresh: saiife blind data refresh --dataset {n}");
            }
        }
    }

    // ------------------------------------------------------ 6/6 Test ----

    /// `<n> personal values sent` and `<a>/<b> numbers checked` from a
    /// footer (R48-4, en or da).
    pub(crate) fn footer_counts(footer: &str) -> (String, String) {
        let mut sent = "?".to_string();
        let mut checked = "?".to_string();
        for part in footer.split('·').map(str::trim) {
            let first = part.split_whitespace().next().unwrap_or("").to_string();
            if part.ends_with("personal values sent") || part.ends_with("personlige værdier sendt")
            {
                sent = first;
            } else if part.ends_with("numbers checked") || part.ends_with("tal tjekket") {
                checked = first;
            }
        }
        (sent, checked)
    }

    /// The method text of a `── method: …` line.
    fn method_of(line: &str) -> String {
        line.strip_prefix("── ")
            .and_then(|x| x.split_once(": "))
            .map(|(_, m)| m.to_string())
            .unwrap_or_else(|| line.to_string())
    }

    /// Step 6: the test question asked, with the preview.
    fn test_step(
        t: &Target,
        a: &InitArgs,
        plan: &Plan,
        st: &Staged,
        p: &mut dyn Prompter,
    ) -> Result<bool, Stop> {
        let first = st.tables.first().map(|x| x.0.as_str()).unwrap_or("");
        let q = test_question(Lang::En, plan.entities.first(), first);
        outln!("{}\"{}\"", head(6, 6, "Test"), sanitize(&q));
        // Root asks only when listed (R47-3).
        let may_ask = call(t, "blind.status", Map::new(), READ_TIMEOUT)
            .ok()
            .and_then(|v| {
                v.get("datasets")?
                    .as_array()?
                    .iter()
                    .find(|d| s(d, "name") == plan.name)
                    .map(|d| {
                        ["user", "approver"]
                            .iter()
                            .any(|k| d["role"].get(*k).and_then(Value::as_bool) == Some(true))
                    })
            })
            .unwrap_or(false);
        if !may_ask {
            outln!(
                "{INDENT}not asked: you are not a user of {} (--users)",
                sanitize(&plan.name)
            );
            return Ok(true);
        }
        // `--yes` is refused for a dataset that needs the preview.
        let yes = a.yes && !plan.preview_required;
        if !yes && !p.is_interactive() {
            outln!("{INDENT}not asked: the method preview needs an answer: run saiife blind init in a terminal, or pass --yes");
            return Ok(true);
        }
        let mut req = args([
            ("question", json!(q)),
            ("dataset", json!(plan.name)),
            ("new_session", json!(true)),
            ("lang", json!("en")),
        ]);
        if yes {
            req.insert("yes".into(), json!(true));
        }
        if a.show_sent {
            req.insert("show_sent".into(), json!(true));
        }
        let (id, mut step) = ask::reply(call(t, "blind.ask", req, ASK_TIMEOUT)?)?;
        let mut shown_method = false;
        for _ in 0..8 {
            match s(&step, "kind") {
                "preview" => {
                    ask::print_envelope(&step);
                    for l in labelled("method:", s(&step, "text")) {
                        outln!("{l}");
                    }
                    shown_method = true;
                    let run = yes
                        || p.line(ask::run_prompt(Lang::En))
                            .map(|l| ask::is_run(&l))
                            .unwrap_or(false);
                    step = ask::answer(t, &id, json!({"run": run}))?;
                }
                "answer" => {
                    ask::print_envelope(&step);
                    if !shown_method {
                        for l in labelled("method:", &method_of(s(&step, "method_line"))) {
                            outln!("{l}");
                        }
                    }
                    let (sent, checked) = footer_counts(s(&step, "footer"));
                    outln!(
                        "{INDENT}{:<17}schema + synthetic rows + 1 question, {} personal values",
                        "sent to cloud:",
                        sanitize(&sent)
                    );
                    let text = format!(
                        "{} (checked: {} numbers from the calculator)",
                        s(&step, "text"),
                        sanitize(&checked)
                    );
                    for l in labelled("answer:", &text) {
                        outln!("{l}");
                    }
                    return Ok(true);
                }
                "refused" => {
                    ask::print_envelope(&step);
                    for l in labelled("refused:", s(&step, "head")) {
                        outln!("{l}");
                    }
                    for l in labelled("", s(&step, "reason")) {
                        outln!("{l}");
                    }
                    return Ok(false);
                }
                "refreshing" => {
                    for l in labelled("", s(&step, "text")) {
                        outln!("{l}");
                    }
                    return Ok(false);
                }
                _ => {
                    ask::end_quietly(t, &id, step.clone());
                    outln!("{INDENT}the test question needed a choice: ask your own with saiife blind ask");
                    return Ok(false);
                }
            }
        }
        Ok(false)
    }

    // ------------------------------------------------------- the runs ----

    /// The dataset's settings before its columns are chosen.
    /// The Rules line (controller ruling: "unless --yes" when the dataset
    /// does not require the preview).
    pub(crate) fn rules_text(k: u32, preview_required: bool) -> String {
        let preview = if preview_required {
            "preview before every run"
        } else {
            "preview before every run unless --yes"
        };
        format!("exact mode by default · k = {k} · {preview} · English, Danish")
    }

    /// The dataset's settings before its columns are chosen. A dataset in
    /// policy keeps its k, users, approvers and preview_required unless a
    /// flag changes them; a change that loosens it (a lower k, a user or
    /// approver added) is refused: no touch can grant it (`blind:loosen`
    /// grants a column's class only), so it is a hand edit of the file.
    /// `preview_required` can only be turned on here.
    fn plan_for(
        t: &Target,
        k: &Known,
        ds: &str,
        a: &DataArgs,
        want_preview: bool,
        existing: Option<&BlindDataset>,
    ) -> Result<PlanStart, Stop> {
        let Some(old) = existing else {
            return Ok(PlanStart {
                users: a.users.clone(),
                approvers: a.approvers.clone(),
                k: a.k,
                preview_required: want_preview,
                base: None,
            });
        };
        let path = policy_file::dataset_path(t, ds).map_err(Stop::Refused)?;
        let shown = sanitize(ds);
        let by_hand = |what: &str| {
            Stop::Refused(format!(
                "{shown} is in policy already, and {what} would loosen it, which saiife blind does not do: edit {} by hand (remove its first line), then saiife policy reload",
                sanitize(&path.display().to_string())
            ))
        };
        let new_k = a.k.or(old.k);
        let eff = |x: Option<u32>| x.or(k.full.k).unwrap_or(DEFAULT_K);
        if eff(new_k) < eff(old.k) {
            return Err(by_hand(&format!(
                "a lower k ({} instead of {})",
                eff(new_k),
                eff(old.k)
            )));
        }
        let list = |given: &[String], had: &[String], what: &str| -> Result<Vec<String>, Stop> {
            if given.is_empty() {
                return Ok(had.to_vec());
            }
            match given.iter().find(|u| !had.contains(u)) {
                Some(u) => Err(by_hand(&format!("adding {what} {}", sanitize(u)))),
                None => Ok(given.to_vec()),
            }
        };
        Ok(PlanStart {
            users: list(&a.users, &old.users, "the user")?,
            approvers: list(&a.approvers, &old.approvers, "the approver")?,
            k: new_k,
            preview_required: old.preview_required || want_preview,
            base: Some(old.clone()),
        })
    }

    /// What [`plan_for`] keeps or sets.
    struct PlanStart {
        users: Vec<String>,
        approvers: Vec<String>,
        k: Option<u32>,
        preview_required: bool,
        base: Option<BlindDataset>,
    }

    impl PlanStart {
        fn plan(self, ds: &str, source: BlindSource) -> Plan {
            Plan {
                name: ds.to_string(),
                source,
                classes: BTreeMap::new(),
                col_alias: BTreeMap::new(),
                table_alias: BTreeMap::new(),
                entities: Vec::new(),
                users: self.users,
                approvers: self.approvers,
                k: self.k,
                preview_required: self.preview_required,
                base: self.base,
            }
        }
    }

    /// The k a stage's previews used: the dataset's in policy, else the
    /// global, else 10.
    fn stage_k(k: &Known, existing: Option<&BlindDataset>) -> u32 {
        existing
            .map(|d| k.full.k_for(d))
            .unwrap_or_else(|| k.full.k.unwrap_or(DEFAULT_K))
    }

    /// `saiife blind init`.
    pub(crate) fn init(t: &Target, a: InitArgs, p: &mut dyn Prompter) -> Result<ExitCode, Stop> {
        if t.is_locked() && !euid_root() {
            return Err(Stop::Refused(NOT_ROOT_INIT.into()));
        }
        let mut undo = Undo::default();
        let r = init_steps(t, &a, p, &mut undo);
        finish(t, r, undo)
    }

    fn init_steps(
        t: &Target,
        a: &InitArgs,
        p: &mut dyn Prompter,
        undo: &mut Undo,
    ) -> Result<Outcome, Stop> {
        let mut k = known(t)?;
        let ds = dataset_name(&a.data, p, "saiife blind init")?;
        let existing = writable(t, &ds, &k)?;
        let shown_k = stage_k(&k, existing.as_ref());
        let start = plan_for(t, &k, &ds, &a.data, a.preview_required, existing.as_ref())?;
        let (source, st) = data_step(t, &a.data, existing.as_ref(), &ds, 6, p, undo)?;
        let mut plan = start.plan(&ds, source);
        columns_step(&a.data, &st, shown_k, 6, "saiife blind init", p, &mut plan)?;
        if !models_step(t, a, &mut k, p, undo)? {
            return Ok(Outcome::Stopped);
        }
        if !cloud_step(t, a, &mut k)? {
            return Ok(Outcome::Stopped);
        }
        let kk = plan.k.or(k.full.k).unwrap_or(DEFAULT_K);
        outln!(
            "{}{}",
            head(5, 6, "Rules"),
            rules_text(kk, plan.preview_required)
        );
        let globals = (k.mine != k.mine0).then_some(&k.mine);
        build(t, &mut plan, globals, &st, p, undo)?;
        let path = policy_file::dataset_path(t, &ds).map_err(Stop::Refused)?;
        let wrote = match globals {
            Some(_) => format!(
                "{} and {}",
                sanitize(&policy_file::globals_path(t).display().to_string()),
                sanitize(&path.display().to_string())
            ),
            None => sanitize(&path.display().to_string()),
        };
        outln!("{INDENT}wrote {wrote}; {} is live", sanitize(&ds));
        let tested = if a.skip_test {
            true
        } else {
            test_step(t, a, &plan, &st, p)?
        };
        refresh_hints(t, &ds);
        if !tested {
            outln!(
                "{INDENT}{} is set up, but the test question was not answered",
                sanitize(&ds)
            );
            return Ok(Outcome::TestFailed);
        }
        outln!("Done. Ask with: saiife blind ask \"…\"");
        Ok(Outcome::Done)
    }

    /// `saiife blind data add`: Data and Columns, then the dataset's file
    /// written and built.
    pub(crate) fn data_add(
        t: &Target,
        a: DataArgs,
        p: &mut dyn Prompter,
    ) -> Result<ExitCode, Stop> {
        if t.is_locked() && !euid_root() {
            return Err(Stop::Refused(NOT_ROOT_ADD.into()));
        }
        let mut undo = Undo::default();
        let r = add_steps(t, &a, p, &mut undo);
        finish(t, r, undo)
    }

    fn add_steps(
        t: &Target,
        a: &DataArgs,
        p: &mut dyn Prompter,
        undo: &mut Undo,
    ) -> Result<Outcome, Stop> {
        let k = known(t)?;
        let ds = dataset_name(a, p, "saiife blind data add")?;
        let existing = writable(t, &ds, &k)?;
        let shown_k = stage_k(&k, existing.as_ref());
        let start = plan_for(t, &k, &ds, a, false, existing.as_ref())?;
        let (source, st) = data_step(t, a, existing.as_ref(), &ds, 2, p, undo)?;
        let mut plan = start.plan(&ds, source);
        columns_step(a, &st, shown_k, 2, "saiife blind data add", p, &mut plan)?;
        build(t, &mut plan, None, &st, p, undo)?;
        let path = policy_file::dataset_path(t, &ds).map_err(Stop::Refused)?;
        outln!("{INDENT}wrote {}", sanitize(&path.display().to_string()));
        outln!("{} is live", sanitize(&ds));
        refresh_hints(t, &ds);
        Ok(Outcome::Done)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn staged() -> Staged {
            Staged::parse(&json!({"tables": [
                {"name": "customers", "rows_band": "about 100", "columns": [
                    {"name": "id", "type": "integer", "guess": "identifier", "uncertain": false,
                     "public_refusal": "holds names or IDs"},
                    {"name": "first_name", "type": "text", "guess": "identifier", "uncertain": false,
                     "public_refusal": "holds names or IDs"},
                    {"name": "last_name", "type": "text", "guess": "identifier", "uncertain": false,
                     "public_refusal": "holds names or IDs"},
                    {"name": "city", "type": "text", "guess": "quasi", "uncertain": false,
                     "public_preview": {"passing": 4, "total": 5}},
                    {"name": "email", "type": "text", "guess": "identifier", "uncertain": false,
                     "public_refusal": "holds names or IDs"}]},
                {"name": "visits", "rows_band": "<100", "columns": [
                    {"name": "visitor", "type": "text", "guess": "sensitive", "uncertain": true,
                     "public_refusal": NO_IDENTIFIER},
                    {"name": "city", "type": "text", "guess": "quasi", "uncertain": false,
                     "public_refusal": NO_IDENTIFIER}]}
            ]}))
        }

        #[test]
        fn fixed_texts() {
            assert_eq!(head(1, 6, "Data"), "1/6 Data      ");
            assert_eq!(head(2, 6, "Columns"), "2/6 Columns   ");
            assert_eq!(
                NOT_ROOT_INIT,
                "saiife blind init writes policy: run it as root (sudo saiife blind init)"
            );
            assert_eq!(
                pin_text(
                    "https://x.test/ner-multi-onnx",
                    "41ab00000000000000000000000000000000000000000000000000000000007c"
                ),
                "ner-multi-onnx  sha256 41ab…7c"
            );
            assert_eq!(
                identifier_prompt("visits", &["visitor", "city"]),
                "Which column identifies the person in visits? (visitor, city) "
            );
            assert_eq!(
                labelled("method:", "a\nb")[0],
                format!("{INDENT}method:          a")
            );
            assert_eq!(
                labelled("method:", "a\nb")[1],
                format!("{INDENT}{}b", " ".repeat(17))
            );
            assert_eq!(
                tables_text(&staged()),
                "2 tables (customers: about 100 rows, visits: under 100 rows)"
            );
        }

        #[test]
        fn rules_line() {
            assert_eq!(
                rules_text(10, true),
                "exact mode by default · k = 10 · preview before every run · English, Danish"
            );
            assert_eq!(
                rules_text(20, false),
                "exact mode by default · k = 20 · preview before every run unless --yes · English, Danish"
            );
        }

        #[test]
        fn test_questions() {
            let e = EntityCfg {
                table: "customers".into(),
                key: "id".into(),
                names: vec!["first_name".into()],
                show: vec![],
                word: Some("customer".into()),
                word_da: Some("kunder".into()),
            };
            assert_eq!(
                test_question(Lang::En, Some(&e), "x"),
                "How many customers are there?"
            );
            assert_eq!(
                test_question(Lang::Da, Some(&e), "x"),
                "Hvor mange kunder er der?"
            );
            assert_eq!(
                test_question(Lang::En, None, "loans"),
                "How many rows does loans have?"
            );
        }

        #[test]
        fn public_marks_and_entities() {
            let st = staged();
            let mut classes: BTreeMap<String, String> =
                st.cols.iter().map(|c| (c.key(), c.guess.clone())).collect();
            assert_eq!(
                set_class(&st, &mut classes, "customers.email", "public", 10).unwrap_err(),
                "customers.email cannot be public: it holds names or IDs"
            );
            assert_eq!(
                set_class(&st, &mut classes, "customers.city", "public", 10).unwrap(),
                "(4 of 5 values pass k = 10)"
            );
            assert!(set_class(&st, &mut classes, "customers.cty", "quasi", 10).is_err());
            assert!(set_class(&st, &mut classes, "customers.city", "secret", 10).is_err());
            classes.insert("customers.city".into(), "quasi".into());
            let g = guess_entities(&st, &classes);
            assert_eq!(g.len(), 1);
            assert_eq!(
                entity_spec(&g[0]),
                "customers:id:first_name+last_name:city:customer:"
            );
            let e =
                parse_entity("customers:id:first_name+last_name:city:customer:kunde", &st).unwrap();
            assert_eq!(e.word_da.as_deref(), Some("kunde"));
            assert!(parse_entity("customers:id", &st).is_err());
            assert!(parse_entity("customers:id:nope", &st).is_err());
            assert_eq!(
                without_identifier(&st, &classes),
                vec!["visits".to_string()]
            );
            classes.insert("visits.visitor".into(), "identifier".into());
            assert!(without_identifier(&st, &classes).is_empty());
        }

        #[test]
        fn commit_refusals_and_footers() {
            assert_eq!(
                no_identifier_table(&format!("table visits {NO_IDENTIFIER}")),
                Some("visits".into())
            );
            assert_eq!(no_identifier_table("table visits is broken"), None);
            assert_eq!(
                footer_counts(
                    "── exact · new method · 0 personal values sent · 1/1 numbers checked"
                ),
                ("0".into(), "1/1".into())
            );
            assert_eq!(
                footer_counts(
                    "── præcis · ny metode · 0 personlige værdier sendt · 2/2 tal tjekket"
                ),
                ("0".into(), "2/2".into())
            );
            assert_eq!(
                method_of("── method: counted the customers"),
                "counted the customers"
            );
            assert!(local_pg("/run/postgresql") && local_pg("localhost") && local_pg("::1"));
            assert!(!local_pg("db.example.test") && !local_pg("10.0.0.1"));
            assert_eq!(
                super::super::parse_kv("a.b=c"),
                Ok(("a.b".into(), "c".into()))
            );
            assert!(super::super::parse_kv("a.b").is_err());
            assert_eq!(singular("companies"), "company");
            assert_eq!(singular("customers"), "customer");
        }
    }
}
