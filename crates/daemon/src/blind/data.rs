//! Dataset import, commit, refresh and removal (plan 47 Task 2; R47-3 to
//! R47-6, rulings P47-5, P47-6, P47-17). The daemon does the I/O; the
//! shield builds (`stage_snapshot`, `propose`, `finish`, `load_manifest`).
//!
//! - `blind.data.stage` reads the source into `stage/` and answers the
//!   classifier's proposals. Nothing is live and nothing is recorded.
//! - `blind.data.commit` builds the staged snapshot with the policy's
//!   classes, makes it live and writes `classes.json` (the baseline).
//! - `blind.data.refresh` re-reads the source and builds, in the background.
//! - `blind.data.rm` shreds the keys and removes the dataset's directory.
//!
//! One build at a time per dataset: the state is `Building` while one runs
//! (an ask gets the refreshing answer; an ask already running keeps its
//! open files). Files holding data are 0600 in 0700 dirs. No answer, record
//! or error text carries a cell value.

use super::audit::{self, BlindRecord};
use super::ops::{role, Roles};
use super::pg::{self, PgSource};
use super::{keys, private_dir, write_private, Blind, DatasetState, LiveHandles, Refusal};
use crate::ops::{Conn, Ctx};
use saiife_ipc::msg::ErrorCode;
use saiife_ipc::peer::PeerCred;
use saiife_policy::blind::{BlindDataset, BlindSource};
use saiife_shield::dataset::{
    finish, load_manifest, propose, stage_snapshot, DatasetDir, Manifest, Proposal,
    MANIFEST_VERSION,
};
use saiife_shield::index::{read_allow, KnownIndex, ALLOW_FILE};
use saiife_shield::lexicon::Lexicon;
use saiife_shield::ner::{NameDetector, SpanLabel};
use saiife_shield::public::{PublicValues, NO_IDENTIFIER};
use saiife_shield::schema::{
    rows_band, ColType, ColumnClass, ColumnInfo, DatasetName, EntitySpec, KeyJoin, Schema,
    TableInfo,
};
use saiife_shield::source::{CsvSource, RowSource, SqliteSource, XlsxSource, MAX_FILE_BYTES};
use saiife_shield::standin::KeySet;
use saiife_shield::ShieldError;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

/// The classes in force, written by every build that went live (R47-6).
pub const CLASSES_FILE: &str = "classes.json";
/// The unspent loosen grants (written by plan 48 after a `blind:loosen` touch).
pub const LOOSEN_FILE: &str = "loosen.json";
/// What `stage` saw (names and types only), for `commit`.
const STAGED_FILE: &str = "staged.json";
/// Where a SQLite source is copied while it is read (`stage/` is emptied by
/// the snapshot, so the copy cannot live there).
const IMPORT_DIR: &str = "import";
const IMPORT_FILE: &str = "source.sqlite";
/// An entity's words when the policy gives none.
const DEFAULT_WORD: &str = "record";
const DEFAULT_WORD_DA: &str = "post";
/// Larger than any classes or grants file.
const MAX_SMALL_JSON: u64 = 16 << 20;

/// `table.column` -> its class.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Classes(pub BTreeMap<String, ColumnClass>);

/// A `blind:loosen` touch's grant: `column` may become `class`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoosenGrant {
    /// `table.column`.
    pub column: String,
    pub class: ColumnClass,
    pub touched_at: String,
    pub by: String,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LoosenFile {
    grants: Vec<LoosenGrant>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Staged {
    snapshot_sha256: String,
    tables: Vec<StagedTable>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StagedTable {
    name: String,
    columns: Vec<(String, ColType)>,
}

/// A snapshot's tables and their typed columns.
type Layout = Vec<(String, Vec<(String, ColType)>)>;

fn bad(text: impl Into<String>) -> Refusal {
    Refusal::new(ErrorCode::BadRequest, text)
}

fn unavailable(text: impl Into<String>) -> Refusal {
    Refusal::new(ErrorCode::Unavailable, text)
}

fn not_in_policy(d: &DatasetName) -> Refusal {
    bad(format!(
        "{d} is not in policy: write policy.d/blind-{d}.toml and reload"
    ))
}

fn class_name(c: ColumnClass) -> &'static str {
    match c {
        ColumnClass::Identifier => "identifier",
        ColumnClass::Quasi => "quasi",
        ColumnClass::Sensitive => "sensitive",
        ColumnClass::FreeText => "free_text",
        ColumnClass::Public => "public",
    }
}

/// The policy's class text; one the policy load did not accept cannot
/// reach here, and anything else is the strictest class.
fn parse_class(s: &str) -> ColumnClass {
    serde_json::from_value(Value::String(s.to_string())).unwrap_or(ColumnClass::Sensitive)
}

/// The schema a build uses (R47-6): each column's policy class (none:
/// `sensitive`), unless that is looser than the baseline's and no grant
/// names the new class; then the baseline's class stays, with a warning.
/// Also the indexes of the grants that were applied.
fn schema_for(
    cfg: &BlindDataset,
    name: &DatasetName,
    layout: &Layout,
    baseline: &Classes,
    grants: &[LoosenGrant],
) -> (Schema, Vec<String>, Vec<usize>) {
    let mut warnings = Vec::new();
    let mut applied = Vec::new();
    let mut tables = Vec::new();
    for (t, cols) in layout {
        let mut columns = Vec::new();
        for (c, ty) in cols {
            let key = format!("{t}.{c}");
            let ccfg = cfg.columns.get(&key);
            let want = ccfg.map_or(ColumnClass::Sensitive, |x| parse_class(&x.class));
            let class = match baseline.0.get(&key) {
                Some(&old) if want.is_looser_than(old) => {
                    match grants
                        .iter()
                        .position(|g| g.column == key && g.class == want)
                    {
                        Some(i) => {
                            applied.push(i);
                            want
                        }
                        None => {
                            warnings.push(format!(
                                "{key} was made {} in policy without a blind:loosen touch; still {}",
                                class_name(want),
                                class_name(old)
                            ));
                            old
                        }
                    }
                }
                _ => want,
            };
            columns.push(ColumnInfo {
                name: c.clone(),
                ty: *ty,
                class,
                alias: ccfg.and_then(|x| x.alias.clone()),
            });
        }
        tables.push(TableInfo {
            name: t.clone(),
            alias: cfg.tables.get(t).and_then(|x| x.alias.clone()),
            rows: 0,
            columns,
        });
    }
    let entities = cfg
        .entity
        .iter()
        .map(|e| EntitySpec {
            table: e.table.clone(),
            key: e.key.clone(),
            names: e.names.clone(),
            show: e.show.clone(),
            word: e.word.clone().unwrap_or_else(|| DEFAULT_WORD.into()),
            word_da: e.word_da.clone().unwrap_or_else(|| DEFAULT_WORD_DA.into()),
        })
        .collect();
    let mut joins: Vec<KeyJoin> = cfg
        .joins
        .iter()
        .map(|j| KeyJoin {
            entity: j.entity.clone(),
            key: j.key.clone(),
            table: j.table.clone(),
            column: j.column.clone(),
        })
        .collect();
    joins.sort();
    joins.dedup();
    let schema = Schema {
        dataset: name.clone(),
        tables,
        entities,
        joins,
    };
    (schema, warnings, applied)
}

/// The effective schema of a built dataset under `cfg` (R47-6), and the
/// warnings `status` shows.
pub fn effective_schema(
    cfg: &BlindDataset,
    m: &Manifest,
    baseline: &Classes,
    grants: &[LoosenGrant],
) -> (Schema, Vec<String>) {
    let (s, w, _) = schema_for(cfg, &m.dataset, &layout_of(&m.schema), baseline, grants);
    (s, w)
}

fn layout_of(s: &Schema) -> Layout {
    s.tables
        .iter()
        .map(|t| {
            (
                t.name.clone(),
                t.columns.iter().map(|c| (c.name.clone(), c.ty)).collect(),
            )
        })
        .collect()
}

/// The loosen warnings of a live dataset under the policy in force.
pub fn warnings(ctx: &Ctx, name: &DatasetName) -> Vec<String> {
    let (Some((cfg, _)), DatasetState::Live { manifest, .. }) =
        (policy_dataset(ctx, name), ctx.blind.state(name))
    else {
        return Vec::new();
    };
    let dir = ctx.blind.dataset_dir(name);
    let (Ok(base), Ok(grants)) = (read_classes(&dir), read_grants(&dir)) else {
        return Vec::new();
    };
    effective_schema(&cfg, &manifest, &base, &grants).1
}

/// The dataset in the policy in force, and its `k`.
fn policy_dataset(ctx: &Ctx, name: &DatasetName) -> Option<(BlindDataset, u32)> {
    let p = ctx.policy();
    let s = p.system?;
    let d = s.blind.dataset.iter().find(|d| d.name == name.as_str())?;
    Some((d.clone(), s.blind.k_for(d)))
}

// ------------------------------------------------------------ files ----

/// A small JSON file of ours: missing is `None`; never through a link.
fn read_small<T: serde::de::DeserializeOwned>(p: &Path) -> io::Result<Option<T>> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(p);
    let f = match f {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut b = Vec::new();
    f.take(MAX_SMALL_JSON + 1).read_to_end(&mut b)?;
    if b.len() as u64 > MAX_SMALL_JSON {
        return Err(io::Error::other("too large"));
    }
    serde_json::from_slice(&b)
        .map(Some)
        .map_err(|_| io::Error::other("not valid"))
}

fn read_classes(dir: &DatasetDir) -> Result<Classes, Refusal> {
    read_small(&dir.root.join(CLASSES_FILE))
        .map(Option::unwrap_or_default)
        .map_err(|e| unavailable(format!("{CLASSES_FILE} cannot be read: {e}")))
}

fn read_grants(dir: &DatasetDir) -> Result<Vec<LoosenGrant>, Refusal> {
    read_small::<LoosenFile>(&dir.root.join(LOOSEN_FILE))
        .map(|f| f.unwrap_or_default().grants)
        .map_err(|e| unavailable(format!("{LOOSEN_FILE} cannot be read: {e}")))
}

fn json_bytes<T: serde::Serialize>(v: &T) -> Vec<u8> {
    // Plain maps and lists of strings: serialising cannot fail.
    serde_json::to_vec_pretty(v).unwrap_or_default()
}

/// Removes `p` (a file, a link or a whole dir), never following a link.
fn remove_entry(p: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(p) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
        Ok(md) if md.is_dir() => std::fs::remove_dir_all(p),
        Ok(_) => std::fs::remove_file(p),
    }
}

// ----------------------------------------------------------- source ----

/// A file source's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileKind {
    Csv,
    Xlsx,
    Sqlite,
}

/// What a build reads from.
enum Input {
    File {
        kind: FileKind,
        file: File,
        name: String,
    },
    Pg(PgSource),
}

fn kind_of(src: &BlindSource) -> &'static str {
    match src {
        BlindSource::Csv { .. } => "csv",
        BlindSource::Xlsx { .. } => "xlsx",
        BlindSource::Sqlite { .. } => "sqlite",
        BlindSource::Postgres { .. } => "postgres",
    }
}

fn file_kind(kind: &str) -> Option<FileKind> {
    match kind {
        "csv" => Some(FileKind::Csv),
        "xlsx" => Some(FileKind::Xlsx),
        "sqlite" => Some(FileKind::Sqlite),
        _ => None,
    }
}

/// The one descriptor a file source is passed as (R47-5).
fn one_file(fds: Vec<std::os::fd::OwnedFd>, kind: &str) -> Result<File, Refusal> {
    let mut fds = fds;
    if fds.len() != 1 {
        return Err(bad(format!(
            "a {kind} source is passed as one open file (the CLI opens it)"
        )));
    }
    let f = File::from(fds.remove(0));
    match f.metadata() {
        Ok(md) if md.is_file() => Ok(f),
        _ => Err(bad("the passed descriptor is not a regular file")),
    }
}

/// Removes the SQLite copy when the read is over.
struct ImportCopy(PathBuf);

impl Drop for ImportCopy {
    fn drop(&mut self) {
        let _ = remove_entry(&self.0);
    }
}

/// `file` copied into `<dataset>/import/source.sqlite` (0600 in 0700): a
/// SQLite source needs a path.
fn copy_import(dir: &DatasetDir, mut file: File) -> io::Result<(ImportCopy, PathBuf)> {
    let d = dir.root.join(IMPORT_DIR);
    remove_entry(&d)?;
    private_dir(&d)?;
    let guard = ImportCopy(d.clone());
    let p = d.join(IMPORT_FILE);
    let mut out = crate::fsx::new_private_file(&p)?;
    let n = io::copy(&mut (&mut file).take(MAX_FILE_BYTES + 1), &mut out)?;
    if n > MAX_FILE_BYTES {
        return Err(io::Error::other("the file is over the size limit"));
    }
    out.sync_all()?;
    Ok((guard, p))
}

/// The source as rows (on the blocking build thread), and the SQLite copy
/// to remove after the snapshot.
fn open_input(
    dir: &DatasetDir,
    input: Input,
) -> Result<(Box<dyn RowSource + Send>, Option<ImportCopy>), Refusal> {
    let shield = |e: ShieldError| shield_refusal(&e);
    Ok(match input {
        Input::Pg(p) => (Box::new(p), None),
        Input::File { kind, file, name } => match kind {
            FileKind::Csv => (
                Box::new(CsvSource::open(Box::new(file), &name).map_err(shield)?),
                None,
            ),
            FileKind::Xlsx => (
                Box::new(XlsxSource::open(file, &name).map_err(shield)?),
                None,
            ),
            FileKind::Sqlite => {
                private_dir(&dir.root).map_err(|e| unavailable(format!("the dataset dir: {e}")))?;
                let (guard, p) = copy_import(dir, file)
                    .map_err(|e| unavailable(format!("could not copy {name}: {e}")))?;
                (
                    Box::new(SqliteSource::open(&p).map_err(shield)?),
                    Some(guard),
                )
            }
        },
    })
}

/// A shield error as an answer. Shield texts name files, tables, columns
/// and rows only, never a value.
fn shield_refusal(e: &ShieldError) -> Refusal {
    match e {
        ShieldError::Source {
            file,
            table: Some(t),
            why,
            ..
        } if file == "policy" && *why == NO_IDENTIFIER => bad(format!("table {t} {NO_IDENTIFIER}")),
        ShieldError::Io(_) | ShieldError::Sqlite(_) => unavailable(e.to_string()),
        _ => bad(e.to_string()),
    }
}

// ------------------------------------------------------------ build ----

/// Holds a dataset in `Building`; dropped without [`BuildGuard::done`], it
/// puts back the state it replaced (a failed build leaves the old one live).
struct BuildGuard {
    blind: Arc<Blind>,
    name: DatasetName,
    previous: Option<DatasetState>,
}

impl BuildGuard {
    fn begin(blind: &Arc<Blind>, name: &DatasetName) -> Result<BuildGuard, Refusal> {
        let previous = blind.begin_build(name)?;
        Ok(BuildGuard {
            blind: Arc::clone(blind),
            name: name.clone(),
            previous: Some(previous),
        })
    }

    fn had_live(&self) -> bool {
        matches!(self.previous, Some(DatasetState::Live { .. }))
    }

    /// The index of the build that was live, for the record scrub.
    fn previous_index(&self) -> Option<Arc<LiveHandles>> {
        match &self.previous {
            Some(DatasetState::Live { open, .. }) => Some(Arc::clone(open)),
            _ => None,
        }
    }

    fn done(mut self, s: DatasetState) {
        self.previous = None;
        self.blind.set_state(&self.name, s);
    }
}

impl Drop for BuildGuard {
    fn drop(&mut self) {
        if let Some(p) = self.previous.take() {
            self.blind.set_state(&self.name, p);
        }
    }
}

/// What a build needs besides the snapshot.
struct BuildIn {
    blind: Arc<Blind>,
    name: DatasetName,
    dir: DatasetDir,
    cfg: BlindDataset,
    k: u32,
    keys: KeySet,
    detector: Option<Arc<dyn NameDetector>>,
}

/// A build that went live.
struct Built {
    manifest: Arc<Manifest>,
    open: Arc<LiveHandles>,
}

/// Ruling P47-6: public values and the names the cloud sees are checked
/// for people's names. With no detector, a schema with public columns is
/// refused (fail closed); without public columns it proceeds.
fn name_check(
    name: &DatasetName,
    detector: Option<&dyn NameDetector>,
    schema: &Schema,
    public: &[PublicValues],
) -> Result<(), Refusal> {
    let has_public = schema
        .tables
        .iter()
        .any(|t| t.columns.iter().any(|c| c.class == ColumnClass::Public));
    let Some(d) = detector else {
        if has_public {
            return Err(unavailable(format!(
                "{name} has public columns, whose values are checked for names first: \
                 saiife blind ner fetch"
            )));
        }
        return Ok(());
    };
    let person = |text: &str| -> Result<bool, Refusal> {
        d.detect(text)
            .map(|spans| spans.iter().any(|s| s.label == SpanLabel::Person))
            .map_err(|_| unavailable("the name detector failed: try again"))
    };
    for t in &schema.tables {
        for c in &t.columns {
            if person(&schema.cloud_name(&t.name, Some(&c.name)))? {
                return Err(bad(format!(
                    "the name of {}.{} looks like a person's name: give it an alias",
                    t.name, c.name
                )));
            }
        }
        if person(&schema.cloud_name(&t.name, None))? {
            return Err(bad(format!(
                "the name of table {} looks like a person's name: give it an alias",
                t.name
            )));
        }
    }
    for pv in public {
        for v in &pv.passing {
            if person(v)? {
                return Err(bad(format!(
                    "{} is public but a value looks like a person's name: mark it quasi",
                    pv.column
                )));
            }
        }
    }
    Ok(())
}

/// `live/`'s files opened for asks, after `load_manifest` checked their
/// hashes (ruling P47-5: the manifest first; the opens verify nothing).
fn open_handles(dir: &DatasetDir, keys: &KeySet) -> Result<LiveHandles, ShieldError> {
    let lexicon = Lexicon::open(&dir.lexicon())?;
    let index = KnownIndex::open(&dir.live(), keys.index_key())?;
    let allow = read_allow(&dir.live().join(ALLOW_FILE))?;
    Ok(LiveHandles {
        lexicon: std::sync::Mutex::new(lexicon),
        index: Some(index),
        allow,
    })
}

/// Builds the staged snapshot of `layout` and opens it (blocking).
fn build(b: BuildIn, layout: &Layout) -> Result<Built, Refusal> {
    let baseline = read_classes(&b.dir)?;
    let grants = read_grants(&b.dir)?;
    let (schema, _warnings, applied) = schema_for(&b.cfg, &b.name, layout, &baseline, &grants);
    let detector = b.detector.as_deref();
    // Before any work: a schema with public columns needs the detector.
    name_check(&b.name, detector, &schema, &[])?;
    let mut verdict: Option<Refusal> = None;
    let mut validate = |m: &Manifest| -> Result<(), String> {
        if let Err(r) = name_check(&b.name, detector, &m.schema, &m.public) {
            verdict = Some(r);
            return Err(String::new());
        }
        // plan 47 T2b: MethodStore::revalidate after plan 45 merges
        Ok(())
    };
    let (blind, name) = (Arc::clone(&b.blind), b.name.clone());
    let built = finish(
        &b.dir,
        &schema,
        b.k,
        &b.keys.index_key(),
        &mut validate,
        &mut |p| blind.progress(&name, p),
    );
    if let Err(e) = built {
        return Err(verdict.unwrap_or_else(|| shield_refusal(&e)));
    }
    let m = load_manifest(&b.dir).map_err(|e| shield_refusal(&e))?;
    let open = open_handles(&b.dir, &b.keys).map_err(|e| shield_refusal(&e))?;
    // The new baseline: the classes now in force; the grants used are spent.
    let mut classes = Classes::default();
    for t in &m.schema.tables {
        for c in &t.columns {
            classes.0.insert(format!("{}.{}", t.name, c.name), c.class);
        }
    }
    write_private(&b.dir.root.join(CLASSES_FILE), &json_bytes(&classes))
        .map_err(|e| unavailable(format!("could not write {CLASSES_FILE}: {e}")))?;
    if !applied.is_empty() {
        let left = LoosenFile {
            grants: grants
                .into_iter()
                .enumerate()
                .filter(|(i, _)| !applied.contains(i))
                .map(|(_, g)| g)
                .collect(),
        };
        write_private(&b.dir.root.join(LOOSEN_FILE), &json_bytes(&left))
            .map_err(|e| unavailable(format!("could not write {LOOSEN_FILE}: {e}")))?;
    }
    Ok(Built {
        manifest: Arc::new(m),
        open: Arc::new(open),
    })
}

/// The dataset's keys, made on its first build (or after a shred).
fn load_or_create(ctx: &Ctx, name: &DatasetName) -> Result<KeySet, Refusal> {
    match keys::load(ctx, name) {
        Ok(k) => Ok(k),
        Err(keys::KeyError::Missing) => keys::create(ctx, name).map_err(|e| e.refusal(name)),
        Err(e) => Err(e.refusal(name)),
    }
}

/// Records the build that just went live (R47-10). An error fails the op.
async fn record_refresh(
    ctx: &Ctx,
    uid: u32,
    built: &Built,
    ms: u64,
    first: bool,
) -> Result<(), String> {
    let m = &built.manifest;
    let r = BlindRecord::Refresh {
        dataset: m.dataset.to_string(),
        snapshot_sha256: m.snapshot_sha256.clone(),
        rows: m
            .rows_bands
            .iter()
            .map(|(t, b)| (t.clone(), b.clone()))
            .collect(),
        index_entries: m.index.entries,
        ms,
        // plan 47 T2b: the methods `MethodStore::revalidate` suspends.
        suspended: Vec::new(),
        first,
    };
    audit::write(ctx, uid, m.dataset.as_str(), r, built.open.index.as_ref()).await
}

/// The commit's answer: names, bands and counts only.
fn summary(m: &Manifest, warnings: Vec<String>) -> Map<String, Value> {
    let mut a = Map::new();
    a.insert("dataset".into(), json!(m.dataset.as_str()));
    a.insert("built_at".into(), json!(m.built_at));
    a.insert("snapshot_sha256".into(), json!(m.snapshot_sha256));
    a.insert(
        "tables".into(),
        json!(m
            .rows_bands
            .iter()
            .map(|(t, b)| json!({"name": t, "rows_band": b}))
            .collect::<Vec<_>>()),
    );
    a.insert("index_entries".into(), json!(m.index.entries));
    a.insert(
        "public".into(),
        json!(m.public.iter().map(|p| &p.column).collect::<Vec<_>>()),
    );
    a.insert("warnings".into(), json!(warnings));
    a
}

fn ms_since(t: Instant) -> u64 {
    u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn join_err(_: tokio::task::JoinError) -> Refusal {
    unavailable("the build stopped unexpectedly")
}

// -------------------------------------------------------------- ops ----

fn dataset_arg(args: &Map<String, Value>) -> Result<DatasetName, Refusal> {
    args.get("dataset")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("dataset is required"))?
        .parse()
        .map_err(|e: ShieldError| bad(e.to_string()))
}

fn manage_refusal(name: &DatasetName) -> Refusal {
    Refusal::new(
        ErrorCode::Forbidden,
        format!("only an admin or an approver of {name} may change its data"),
    )
}

async fn may_manage(ctx: &Ctx, peer: &PeerCred, cfg: Option<&BlindDataset>) -> bool {
    let r: Roles = role(ctx, peer, cfg).await;
    r.may_manage()
}

/// `blind.data.stage {dataset, kind, file_name?}` (+ one fd for a file
/// kind): the snapshot in `stage/` and the proposals. Records nothing.
pub async fn stage(
    ctx: &Arc<Ctx>,
    conn: &Conn,
    args: &Map<String, Value>,
) -> Result<Value, Refusal> {
    let fds = conn.take_fds();
    let name = dataset_arg(args)?;
    let kind = args
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("kind is required: csv, xlsx, sqlite or postgres"))?
        .to_string();
    let policy = policy_dataset(ctx, &name);
    if !may_manage(ctx, &conn.peer, policy.as_ref().map(|p| &p.0)).await {
        return Err(manage_refusal(&name));
    }
    if let Some((cfg, _)) = &policy {
        if kind_of(&cfg.source) != kind {
            return Err(bad(format!(
                "{name} is a {} source in policy",
                kind_of(&cfg.source)
            )));
        }
    }
    let k = match &policy {
        Some((_, k)) => *k,
        None => ctx
            .policy()
            .system
            .map_or(saiife_policy::blind::DEFAULT_K, |s| {
                s.blind.k.unwrap_or(saiife_policy::blind::DEFAULT_K)
            }),
    };
    let input = match file_kind(&kind) {
        Some(fk) => Input::File {
            kind: fk,
            file: one_file(fds, &kind)?,
            name: args
                .get("file_name")
                .and_then(Value::as_str)
                .map_or_else(|| format!("{name}.{kind}"), base_name),
        },
        None if kind == "postgres" => {
            let Some((cfg, _)) = &policy else {
                return Err(not_in_policy(&name));
            };
            drop(fds);
            let guard = BuildGuard::begin(&ctx.blind, &name)?;
            let p = pg::pg_source(ctx, &cfg.source).await.map_err(unavailable)?;
            return run_stage(ctx, guard, name, Input::Pg(p), k).await;
        }
        None => return Err(bad("kind must be csv, xlsx, sqlite or postgres")),
    };
    let guard = BuildGuard::begin(&ctx.blind, &name)?;
    run_stage(ctx, guard, name, input, k).await
}

fn base_name(s: &str) -> String {
    Path::new(s)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("data")
        .to_string()
}

async fn run_stage(
    ctx: &Arc<Ctx>,
    guard: BuildGuard,
    name: DatasetName,
    input: Input,
    k: u32,
) -> Result<Value, Refusal> {
    let dir = ctx.blind.dataset_dir(&name);
    let blind = Arc::clone(&ctx.blind);
    tokio::task::spawn_blocking(move || {
        // The state goes back to what it was when this is over.
        let _guard = guard;
        private_dir(&dir.root).map_err(|e| unavailable(format!("the dataset dir: {e}")))?;
        remove_entry(&dir.root.join(STAGED_FILE))
            .map_err(|e| unavailable(format!("could not clear {STAGED_FILE}: {e}")))?;
        let (mut src, copy) = open_input(&dir, input)?;
        let info = stage_snapshot(&dir, src.as_mut(), &mut |p| blind.progress(&name, p))
            .map_err(|e| shield_refusal(&e));
        drop(src);
        drop(copy);
        let info = info?;
        let staged = Staged {
            snapshot_sha256: info.sha256.clone(),
            tables: info
                .tables
                .iter()
                .map(|(t, _, _, cols)| StagedTable {
                    name: t.clone(),
                    columns: cols.iter().map(|(c, _, ty)| (c.clone(), *ty)).collect(),
                })
                .collect(),
        };
        write_private(&dir.root.join(STAGED_FILE), &json_bytes(&staged))
            .map_err(|e| unavailable(format!("could not write {STAGED_FILE}: {e}")))?;
        let props = propose(&info.path, k).map_err(|e| shield_refusal(&e))?;
        let tables: Vec<Value> = info
            .tables
            .iter()
            .map(|(t, _, rows, _)| {
                let cols: Vec<Value> = props
                    .iter()
                    .filter(|p| &p.table == t)
                    .map(proposal_json)
                    .collect();
                json!({"name": t, "rows_band": rows_band(*rows), "columns": cols})
            })
            .collect();
        let mut a = Map::new();
        a.insert("tables".into(), Value::Array(tables));
        Ok(Value::Object(a))
    })
    .await
    .map_err(join_err)?
}

/// One column's proposal: classes, scores and counts, never a value.
fn proposal_json(p: &Proposal) -> Value {
    let mut c = Map::new();
    c.insert("name".into(), json!(p.column));
    c.insert("type".into(), json!(p.ty));
    c.insert("guess".into(), json!(p.guess.class));
    c.insert("confidence".into(), json!(p.guess.confidence));
    c.insert("uncertain".into(), json!(p.uncertain));
    if let Some(r) = p.public_refusal {
        c.insert("public_refusal".into(), json!(r));
    }
    if let Some(pv) = &p.public_preview {
        c.insert(
            "public_preview".into(),
            json!({"passing": pv.passing.len(), "total": pv.total_distinct}),
        );
    }
    Value::Object(c)
}

/// `blind.data.commit {dataset}`: builds the staged snapshot with the
/// policy's classes, swaps it live, writes `classes.json` and records
/// `blind_refresh` (first). The dataset must be in the policy in force.
pub async fn commit(
    ctx: &Arc<Ctx>,
    peer: &PeerCred,
    args: &Map<String, Value>,
) -> Result<Value, Refusal> {
    let name = dataset_arg(args)?;
    let started = Instant::now();
    let (cfg, k) = policy_dataset(ctx, &name).ok_or_else(|| not_in_policy(&name))?;
    if !may_manage(ctx, peer, Some(&cfg)).await {
        return Err(manage_refusal(&name));
    }
    let guard = BuildGuard::begin(&ctx.blind, &name)?;
    let dir = ctx.blind.dataset_dir(&name);
    let nothing = || {
        bad(format!(
            "{name} has nothing staged: saiife blind data stage --dataset {name}"
        ))
    };
    let staged: Staged = read_small(&dir.root.join(STAGED_FILE))
        .map_err(|e| unavailable(format!("{STAGED_FILE} cannot be read: {e}")))?
        .ok_or_else(nothing)?;
    if !dir.stage().is_dir() {
        return Err(nothing());
    }
    let layout: Layout = staged
        .tables
        .into_iter()
        .map(|t| (t.name, t.columns))
        .collect();
    let keys = load_or_create(ctx, &name)?;
    let b = BuildIn {
        blind: Arc::clone(&ctx.blind),
        name: name.clone(),
        dir: dir.clone(),
        cfg: cfg.clone(),
        k,
        keys,
        detector: ctx.blind.detector(),
    };
    let built = tokio::task::spawn_blocking(move || build(b, &layout))
        .await
        .map_err(join_err)??;
    guard.done(DatasetState::Live {
        manifest: Arc::clone(&built.manifest),
        open: Arc::clone(&built.open),
    });
    ctx.blind.set_build_error(&name, None);
    let _ = remove_entry(&dir.root.join(STAGED_FILE));
    record_refresh(ctx, peer.uid, &built, ms_since(started), true)
        .await
        .map_err(|e| unavailable(format!("{name} is live but could not be recorded: {e}")))?;
    let w = warnings(ctx, &name);
    Ok(Value::Object(summary(&built.manifest, w)))
}

/// `blind.data.refresh {dataset}` (+ one fd for a file source): answers at
/// once; the build runs on a blocking task, `status` shows its phase, and
/// it records `blind_refresh` when live.
pub async fn refresh(
    ctx: &Arc<Ctx>,
    conn: &Conn,
    args: &Map<String, Value>,
) -> Result<Value, Refusal> {
    let fds = conn.take_fds();
    let name = dataset_arg(args)?;
    let started = Instant::now();
    let (cfg, k) = policy_dataset(ctx, &name).ok_or_else(|| not_in_policy(&name))?;
    if !may_manage(ctx, &conn.peer, Some(&cfg)).await {
        return Err(manage_refusal(&name));
    }
    let kind = kind_of(&cfg.source);
    let file = match &cfg.source {
        BlindSource::Csv { file_name }
        | BlindSource::Xlsx { file_name }
        | BlindSource::Sqlite { file_name } => Some((
            file_kind(kind).unwrap_or(FileKind::Csv),
            one_file(fds, kind)?,
            base_name(file_name),
        )),
        BlindSource::Postgres { .. } => {
            drop(fds);
            None
        }
    };
    let guard = BuildGuard::begin(&ctx.blind, &name)?;
    let keys = load_or_create(ctx, &name)?;
    let first = !guard.had_live();
    let uid = conn.peer.uid;
    let b = BuildIn {
        blind: Arc::clone(&ctx.blind),
        name: name.clone(),
        dir: ctx.blind.dataset_dir(&name),
        cfg: cfg.clone(),
        k,
        keys,
        detector: ctx.blind.detector(),
    };
    let task_ctx = Arc::clone(ctx);
    let h = tokio::spawn(async move {
        let ctx = task_ctx;
        let name = b.name.clone();
        let input = match file {
            Some((kind, file, name)) => Ok(Input::File { kind, file, name }),
            None => pg::pg_source(&ctx, &cfg.source)
                .await
                .map(Input::Pg)
                .map_err(unavailable),
        };
        let res = match input {
            Err(r) => Err(r),
            Ok(input) => tokio::task::spawn_blocking(move || refresh_build(b, input))
                .await
                .unwrap_or_else(|e| Err(join_err(e))),
        };
        match res {
            Ok(built) => {
                guard.done(DatasetState::Live {
                    manifest: Arc::clone(&built.manifest),
                    open: Arc::clone(&built.open),
                });
                let rec = record_refresh(&ctx, uid, &built, ms_since(started), first).await;
                ctx.blind.set_build_error(
                    &name,
                    rec.err()
                        .map(|e| format!("{name} is live but could not be recorded: {e}")),
                );
            }
            Err(r) => {
                drop(guard);
                ctx.blind.set_build_error(&name, Some(r.text));
            }
        }
    });
    ctx.blind.track_build(h);
    let mut a = Map::new();
    a.insert("started".into(), Value::Bool(true));
    Ok(Value::Object(a))
}

/// The snapshot from `input`, then the build (blocking).
fn refresh_build(b: BuildIn, input: Input) -> Result<Built, Refusal> {
    // This build replaces any staged one: a later commit must not pair an
    // old `staged.json` with this stage.
    remove_entry(&b.dir.root.join(STAGED_FILE))
        .map_err(|e| unavailable(format!("could not clear {STAGED_FILE}: {e}")))?;
    let (mut src, copy) = open_input(&b.dir, input)?;
    let (blind, name) = (Arc::clone(&b.blind), b.name.clone());
    let info = stage_snapshot(&b.dir, src.as_mut(), &mut |p| blind.progress(&name, p))
        .map_err(|e| shield_refusal(&e));
    drop(src);
    drop(copy);
    let info = info?;
    let layout: Layout = info
        .tables
        .iter()
        .map(|(t, _, _, cols)| {
            (
                t.clone(),
                cols.iter().map(|(c, _, ty)| (c.clone(), *ty)).collect(),
            )
        })
        .collect();
    build(b, &layout)
}

/// `blind.data.rm {dataset}`: records `blind_keys` (delete, "dataset
/// removed"), shreds the keys (R47-2) and removes the dataset's directory.
/// A dataset that is not there is not an error.
pub async fn rm(
    ctx: &Arc<Ctx>,
    peer: &PeerCred,
    args: &Map<String, Value>,
) -> Result<Value, Refusal> {
    let name = dataset_arg(args)?;
    let cfg = policy_dataset(ctx, &name).map(|p| p.0);
    if !may_manage(ctx, peer, cfg.as_ref()).await {
        return Err(manage_refusal(&name));
    }
    let guard = BuildGuard::begin(&ctx.blind, &name)?;
    let dir = ctx.blind.dataset_dir(&name);
    let mut a = Map::new();
    if std::fs::symlink_metadata(&dir.root).is_err() {
        guard.done(DatasetState::Absent);
        a.insert("removed".into(), Value::Bool(false));
        return Ok(Value::Object(a));
    }
    let version = keys::load(ctx, &name).map_or(0, |k| k.version);
    let live = guard.previous_index();
    // The record first: a removal that cannot be recorded does not happen.
    audit::write(
        ctx,
        peer.uid,
        name.as_str(),
        BlindRecord::Keys {
            dataset: name.to_string(),
            action: "delete",
            version,
            touch: None,
            reason: Some("dataset removed"),
        },
        live.as_ref().and_then(|h| h.index.as_ref()),
    )
    .await
    .map_err(|e| unavailable(format!("the removal of {name} could not be recorded: {e}")))?;
    drop(live);
    keys::shred(ctx, &name).map_err(|e| e.refusal(&name))?;
    let root = dir.root.clone();
    tokio::task::spawn_blocking(move || {
        remove_entry(&root)?;
        match root.parent() {
            Some(p) => crate::fsx::sync_dir(p),
            None => Ok(()),
        }
    })
    .await
    .map_err(join_err)?
    .map_err(|e| unavailable(format!("could not remove {name}: {e}")))?;
    guard.done(DatasetState::Absent);
    ctx.blind.set_build_error(&name, None);
    a.insert("removed".into(), Value::Bool(true));
    Ok(Value::Object(a))
}

// ------------------------------------------------------------ start ----

/// The state of a dataset found on disk at start: live when its manifest,
/// keys and files open; otherwise why not (never unkeyed).
fn reopen(ctx: &Ctx, name: &DatasetName) -> DatasetState {
    let dir = ctx.blind.dataset_dir(name);
    if std::fs::symlink_metadata(dir.live()).is_err() {
        return DatasetState::Absent;
    }
    let again = format!("saiife blind data refresh --dataset {name}");
    // Once, before the opens (ruling P47-5).
    let m = match load_manifest(&dir) {
        Ok(m) => m,
        Err(e) => {
            return DatasetState::NeedsRefresh(format!("{name} cannot be opened ({e}): {again}"))
        }
    };
    if m.v < MANIFEST_VERSION {
        return DatasetState::NeedsRefresh(format!(
            "{name} was built by an older saiife that counted rows, not people: {again}"
        ));
    }
    let keys = match keys::load(ctx, name) {
        Ok(k) => k,
        Err(e) => return DatasetState::NeedsRefresh(e.refusal(name).text),
    };
    match open_handles(&dir, &keys) {
        Ok(open) => DatasetState::Live {
            manifest: Arc::new(m),
            open: Arc::new(open),
        },
        Err(e) => DatasetState::NeedsRefresh(format!("{name} cannot be opened ({e}): {again}")),
    }
}

/// At daemon start: every dataset with a live build is opened again.
pub fn reopen_all(ctx: &Ctx) {
    let dir = ctx.blind.root.join("datasets");
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return;
    };
    for e in rd.flatten() {
        let Some(name) = e
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<DatasetName>().ok())
        else {
            continue;
        };
        if !e.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        match reopen(ctx, &name) {
            DatasetState::Absent => {}
            s => ctx.blind.set_state(&name, s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_name_tables_not_values() {
        let e = ShieldError::Source {
            file: "policy".into(),
            table: Some("invoices".into()),
            column: None,
            row: None,
            why: NO_IDENTIFIER,
        };
        let r = shield_refusal(&e);
        assert_eq!(r.code, ErrorCode::BadRequest);
        assert_eq!(
            r.text,
            "table invoices holds personal data but no column identifies the person; \
             choose the column that identifies the person"
        );
        assert_eq!(
            shield_refusal(&ShieldError::Io("x".into())).code,
            ErrorCode::Unavailable
        );
    }

    #[test]
    fn classes_round_trip() {
        let mut c = Classes::default();
        c.0.insert("t.a".into(), ColumnClass::FreeText);
        let b = json_bytes(&c);
        assert_eq!(
            serde_json::from_slice::<Value>(&b).unwrap(),
            json!({"t.a": "free_text"})
        );
        assert_eq!(serde_json::from_slice::<Classes>(&b).unwrap(), c);
        assert_eq!(parse_class("free_text"), ColumnClass::FreeText);
        assert_eq!(parse_class("nonsense"), ColumnClass::Sensitive);
    }
}
