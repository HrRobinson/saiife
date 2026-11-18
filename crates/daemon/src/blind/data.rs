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
use super::ops::{effective_approvers, role, role_listed, Roles};
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
use saiife_shield::methods::MethodStore;
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
/// The users and approvers the dataset was last built with (S3).
const ACCESS_FILE: &str = "access.json";
/// The dataset's approved methods (plan 45).
const METHODS_FILE: &str = "methods.json";
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
    /// [`source_id`] of what was read.
    source: String,
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
    // P47-22: no readable baseline is the live build's classes.
    let base = read_small::<Classes>(&dir.root.join(CLASSES_FILE))
        .ok()
        .flatten()
        .unwrap_or_else(|| classes_of(&manifest.schema));
    let grants = read_grants(&dir).unwrap_or_default();
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

/// Holds a dataset in `Building`. Dropped without [`BuildGuard::done`], it
/// puts back the state it replaced (a build that failed before its swap
/// leaves the old one live). Both go through [`Blind::end_build`], so keys
/// shredded meanwhile never end `Live`.
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

    /// The build that was live: its handles (the record scrub) and manifest.
    fn previous_live(&self) -> Option<(Arc<Manifest>, Arc<LiveHandles>)> {
        match &self.previous {
            Some(DatasetState::Live { manifest, open }) => {
                Some((Arc::clone(manifest), Arc::clone(open)))
            }
            _ => None,
        }
    }

    fn done(mut self, s: DatasetState) {
        self.previous = None;
        self.blind.end_build(&self.name, s);
    }
}

impl Drop for BuildGuard {
    fn drop(&mut self) {
        if let Some(p) = self.previous.take() {
            self.blind.end_build(&self.name, p);
        }
    }
}

/// Who may manage a dataset whose policy entry is gone (S3): the users and
/// approvers it was last built with. Written with every build.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Access {
    users: Vec<String>,
    /// The approvers in force then (the dataset's, or `[approval]`'s).
    approvers: Vec<String>,
}

/// What a build needs besides the snapshot.
struct BuildIn {
    ctx: Arc<Ctx>,
    /// The runtime the record is written on (from the blocking thread).
    rt: tokio::runtime::Handle,
    name: DatasetName,
    dir: DatasetDir,
    cfg: BlindDataset,
    k: u32,
    keys: KeySet,
    detector: Option<Arc<dyn NameDetector>>,
    access: Access,
    /// The build that was live, if any.
    prev: Option<Arc<Manifest>>,
    uid: u32,
    first: bool,
    started: Instant,
}

/// A build that went live.
struct Built {
    manifest: Arc<Manifest>,
    open: Arc<LiveHandles>,
}

/// Why a build did not go live.
enum BuildErr {
    /// Before the swap: `live/` and the state are as they were.
    Before(Refusal),
    /// After the swap: the new build is on disk but cannot be used; the
    /// dataset ends `NeedsRefresh`, never the old `Live` (ruling P47-21).
    After(Refusal),
}

/// The state a build that failed after its swap leaves.
fn after_swap(name: &DatasetName) -> DatasetState {
    DatasetState::NeedsRefresh(format!(
        "{name} was rebuilt but cannot be opened: saiife blind data refresh --dataset {name}"
    ))
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

fn classes_of(s: &Schema) -> Classes {
    let mut classes = Classes::default();
    for t in &s.tables {
        for c in &t.columns {
            classes.0.insert(format!("{}.{}", t.name, c.name), c.class);
        }
    }
    classes
}

/// The class baseline (R47-6). With a live build, a missing or unreadable
/// `classes.json` falls back to the live manifest's classes (ruling
/// P47-22): a lost file must not let a loosening through.
fn baseline_for(b: &BuildIn) -> Result<Classes, Refusal> {
    let read = read_small::<Classes>(&b.dir.root.join(CLASSES_FILE));
    let live = std::fs::symlink_metadata(b.dir.live()).is_ok();
    match (read, live) {
        (Ok(Some(c)), _) => Ok(c),
        (Ok(None), false) => Ok(Classes::default()),
        (Err(e), false) => Err(unavailable(format!("{CLASSES_FILE} cannot be read: {e}"))),
        (_, true) => {
            let m = match &b.prev {
                Some(m) => Arc::clone(m),
                None => Arc::new(load_manifest(&b.dir).map_err(|_| {
                    unavailable(format!(
                        "the class baseline of {0} cannot be read: \
                         saiife blind data rm --dataset {0} starts over",
                        b.name
                    ))
                })?),
            };
            Ok(classes_of(&m.schema))
        }
    }
}

/// Re-validates the dataset's approved methods against the new build `m`
/// (spec §2.1.1, plan 45). Returns the updated store (to be saved after the
/// swap) and the ids newly suspended. A broken method never refuses the
/// build; an unreadable methods file does (fail closed, fixed text).
fn revalidate_methods(b: &BuildIn, m: &Manifest) -> Result<(MethodStore, Vec<String>), Refusal> {
    let mut store = MethodStore::load(&b.dir.root.join(METHODS_FILE)).map_err(|_| {
        unavailable(format!(
            "{} was not changed: its approved methods cannot be read",
            b.name
        ))
    })?;
    let suspended = store
        .revalidate(&m.schema, &m.public)
        .into_iter()
        .filter(|(_, r)| r.is_err())
        .map(|(id, _)| id)
        .collect();
    Ok((store, suspended))
}

/// Records the build `m` before its swap (ruling P47-21): the index for the
/// scrub is the staged one. An error stops the build: nothing is swapped.
fn record_in_stage(b: &BuildIn, m: &Manifest, suspended: Vec<String>) -> Result<(), Refusal> {
    let index =
        KnownIndex::open(&b.dir.stage(), b.keys.index_key()).map_err(|e| shield_refusal(&e))?;
    let r = BlindRecord::Refresh {
        dataset: m.dataset.to_string(),
        snapshot_sha256: m.snapshot_sha256.clone(),
        rows: m
            .rows_bands
            .iter()
            .map(|(t, band)| (t.clone(), band.clone()))
            .collect(),
        index_entries: m.index.entries,
        ms: ms_since(b.started),
        suspended,
        first: b.first,
    };
    b.rt.block_on(audit::write(
        &b.ctx,
        b.uid,
        b.name.as_str(),
        r,
        Some(&index),
    ))
    .map_err(|e| {
        unavailable(format!(
            "{} was not changed: the build could not be recorded: {e}",
            b.name
        ))
    })
}

/// Builds the staged snapshot of `layout`, records it, swaps it live and
/// opens it (blocking).
fn build(b: BuildIn, layout: &Layout) -> Result<Built, BuildErr> {
    use BuildErr::{After, Before};
    let baseline = baseline_for(&b).map_err(Before)?;
    let grants = read_grants(&b.dir).map_err(Before)?;
    let (schema, _warnings, applied) = schema_for(&b.cfg, &b.name, layout, &baseline, &grants);
    let detector = b.detector.as_deref();
    // Before any work: a schema with public columns needs the detector.
    name_check(&b.name, detector, &schema, &[]).map_err(Before)?;
    write_private(&b.dir.root.join(ACCESS_FILE), &json_bytes(&b.access))
        .map_err(|e| Before(unavailable(format!("could not write {ACCESS_FILE}: {e}"))))?;
    let mut verdict: Option<Refusal> = None;
    // The methods as re-validated: saved only once the swap has happened.
    let mut methods: Option<(MethodStore, Vec<String>)> = None;
    let mut validate = |m: &Manifest| -> Result<(), String> {
        // P47-21 order: name check, re-validation, record.
        let r = name_check(&b.name, detector, &m.schema, &m.public)
            .and_then(|()| revalidate_methods(&b, m))
            .and_then(|(store, suspended)| {
                let r = record_in_stage(&b, m, suspended.clone());
                methods = Some((store, suspended));
                r
            });
        r.map_err(|r| {
            verdict = Some(r);
            String::new()
        })
    };
    let (blind, name) = (Arc::clone(&b.ctx.blind), b.name.clone());
    let built = finish(
        &b.dir,
        &schema,
        b.k,
        &b.keys.index_key(),
        &mut validate,
        &mut |p| blind.progress(&name, p),
    );
    if let Err(e) = built {
        return Err(Before(verdict.unwrap_or_else(|| shield_refusal(&e))));
    }
    // Swapped: from here a failure leaves the dataset needing a refresh.
    if let Some((store, suspended)) = methods {
        if !suspended.is_empty() {
            store
                .save(&b.dir.root.join(METHODS_FILE))
                .map_err(|e| After(shield_refusal(&e)))?;
        }
    }
    let m = load_manifest(&b.dir).map_err(|e| After(shield_refusal(&e)))?;
    let open = open_handles(&b.dir, &b.keys).map_err(|e| After(shield_refusal(&e)))?;
    // The new baseline: the classes now in force; the grants used are spent.
    write_private(
        &b.dir.root.join(CLASSES_FILE),
        &json_bytes(&classes_of(&m.schema)),
    )
    .map_err(|e| After(unavailable(format!("could not write {CLASSES_FILE}: {e}"))))?;
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
            .map_err(|e| After(unavailable(format!("could not write {LOOSEN_FILE}: {e}"))))?;
    }
    Ok(Built {
        manifest: Arc::new(m),
        open: Arc::new(open),
    })
}

/// Ends a build's guard by its result: live, as it was (before the swap),
/// or needing a refresh (after it). The refusal, if any.
fn end_build(
    guard: BuildGuard,
    name: &DatasetName,
    res: Result<Built, BuildErr>,
) -> Result<Arc<Manifest>, Refusal> {
    match res {
        Ok(built) => {
            let m = Arc::clone(&built.manifest);
            guard.done(DatasetState::Live {
                manifest: built.manifest,
                open: built.open,
            });
            Ok(m)
        }
        Err(BuildErr::Before(r)) => {
            drop(guard);
            Err(r)
        }
        Err(BuildErr::After(r)) => {
            guard.done(after_swap(name));
            Err(r)
        }
    }
}

/// The dataset's keys, made on its first build (or after a shred).
fn load_or_create(ctx: &Ctx, name: &DatasetName) -> Result<KeySet, Refusal> {
    match keys::load(ctx, name) {
        Ok(k) => Ok(k),
        Err(keys::KeyError::Missing) => keys::create(ctx, name).map_err(|e| e.refusal(name)),
        Err(e) => Err(e.refusal(name)),
    }
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

/// R47-3 with the policy entry. Without one (S3): the users and approvers
/// the dataset was last built with; none known (or unreadable): admins only.
async fn may_manage(
    ctx: &Ctx,
    peer: &PeerCred,
    name: &DatasetName,
    cfg: Option<&BlindDataset>,
) -> bool {
    let r: Roles = match cfg {
        Some(c) => role(ctx, peer, Some(c)).await,
        None => {
            let p = ctx.blind.dataset_dir(name).root.join(ACCESS_FILE);
            let a = read_small::<Access>(&p).ok().flatten().unwrap_or_default();
            role_listed(ctx, peer, &a.users, &a.approvers).await
        }
    };
    r.may_manage()
}

/// The identity of a source (S5): its kind and file name, or its database,
/// user and tables; a hash, no values.
fn source_id(src: &BlindSource) -> String {
    let v = match src {
        BlindSource::Csv { file_name }
        | BlindSource::Xlsx { file_name }
        | BlindSource::Sqlite { file_name } => json!([kind_of(src), base_name(file_name)]),
        BlindSource::Postgres {
            host,
            port,
            dbname,
            user,
            tables,
            ..
        } => json!(["postgres", host, port, dbname, user, tables]),
    };
    let d = ring::digest::digest(&ring::digest::SHA256, v.to_string().as_bytes());
    crate::api_ops::hex(d.as_ref())
}

fn file_source(kind: FileKind, file_name: String) -> BlindSource {
    match kind {
        FileKind::Csv => BlindSource::Csv { file_name },
        FileKind::Xlsx => BlindSource::Xlsx { file_name },
        FileKind::Sqlite => BlindSource::Sqlite { file_name },
    }
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
    if !may_manage(ctx, &conn.peer, &name, policy.as_ref().map(|p| &p.0)).await {
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
        Some(fk) => {
            let policy_name = match policy.as_ref().map(|p| &p.0.source) {
                Some(
                    BlindSource::Csv { file_name }
                    | BlindSource::Xlsx { file_name }
                    | BlindSource::Sqlite { file_name },
                ) => Some(base_name(file_name)),
                _ => None,
            };
            let file_name = args
                .get("file_name")
                .and_then(Value::as_str)
                .map(base_name)
                .or(policy_name)
                .unwrap_or_else(|| format!("{name}.{kind}"));
            Input::File {
                kind: fk,
                file: one_file(fds, &kind)?,
                name: file_name,
            }
        }
        None if kind == "postgres" => {
            let Some((cfg, _)) = &policy else {
                return Err(not_in_policy(&name));
            };
            drop(fds);
            let guard = BuildGuard::begin(&ctx.blind, &name)?;
            let p = pg::pg_source(ctx, &cfg.source).await.map_err(unavailable)?;
            let id = source_id(&cfg.source);
            return run_stage(ctx, guard, name, Input::Pg(p), id, k).await;
        }
        None => return Err(bad("kind must be csv, xlsx, sqlite or postgres")),
    };
    let id = match &input {
        Input::File { kind, name, .. } => source_id(&file_source(*kind, name.clone())),
        Input::Pg(_) => String::new(),
    };
    let guard = BuildGuard::begin(&ctx.blind, &name)?;
    run_stage(ctx, guard, name, input, id, k).await
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
    source: String,
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
            source,
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

/// The users and approvers in force for `cfg` (kept for S3).
fn access_of(ctx: &Ctx, cfg: &BlindDataset) -> Access {
    Access {
        users: cfg.users.clone(),
        approvers: effective_approvers(ctx, cfg),
    }
}

/// `blind.data.commit {dataset}`: builds the staged snapshot with the
/// policy's classes, records `blind_refresh` (first) before the swap, then
/// swaps it live and writes `classes.json`. The dataset must be in the
/// policy in force, staged from the source the policy names.
pub async fn commit(
    ctx: &Arc<Ctx>,
    peer: &PeerCred,
    args: &Map<String, Value>,
) -> Result<Value, Refusal> {
    let name = dataset_arg(args)?;
    let started = Instant::now();
    let (cfg, k) = policy_dataset(ctx, &name).ok_or_else(|| not_in_policy(&name))?;
    if !may_manage(ctx, peer, &name, Some(&cfg)).await {
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
    if staged.source != source_id(&cfg.source) {
        return Err(bad(format!(
            "{name} was staged from another source than the policy names: \
             saiife blind data stage --dataset {name}"
        )));
    }
    let layout: Layout = staged
        .tables
        .into_iter()
        .map(|t| (t.name, t.columns))
        .collect();
    let keys = load_or_create(ctx, &name)?;
    let b = BuildIn {
        ctx: Arc::clone(ctx),
        rt: tokio::runtime::Handle::current(),
        name: name.clone(),
        dir: dir.clone(),
        access: access_of(ctx, &cfg),
        cfg,
        k,
        keys,
        detector: ctx.blind.detector(),
        prev: guard.previous_live().map(|p| p.0),
        uid: peer.uid,
        first: true,
        started,
    };
    let res = tokio::task::spawn_blocking(move || build(b, &layout))
        .await
        .unwrap_or_else(|e| Err(BuildErr::After(join_err(e))));
    let m = end_build(guard, &name, res)?;
    ctx.blind.set_build_error(&name, None);
    let _ = remove_entry(&dir.root.join(STAGED_FILE));
    let w = warnings(ctx, &name);
    Ok(Value::Object(summary(&m, w)))
}

/// `blind.data.refresh {dataset}` (+ one fd for a file source): answers at
/// once; the build runs on a blocking task, `status` shows its phase, and
/// it records `blind_refresh` before its swap.
pub async fn refresh(
    ctx: &Arc<Ctx>,
    conn: &Conn,
    args: &Map<String, Value>,
) -> Result<Value, Refusal> {
    let fds = conn.take_fds();
    let name = dataset_arg(args)?;
    let started = Instant::now();
    let (cfg, k) = policy_dataset(ctx, &name).ok_or_else(|| not_in_policy(&name))?;
    if !may_manage(ctx, &conn.peer, &name, Some(&cfg)).await {
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
    let source = cfg.source.clone();
    let b = BuildIn {
        ctx: Arc::clone(ctx),
        rt: tokio::runtime::Handle::current(),
        name: name.clone(),
        dir: ctx.blind.dataset_dir(&name),
        access: access_of(ctx, &cfg),
        cfg,
        k,
        keys,
        detector: ctx.blind.detector(),
        prev: guard.previous_live().map(|p| p.0),
        uid: conn.peer.uid,
        first: !guard.had_live(),
        started,
    };
    let task_ctx = Arc::clone(ctx);
    let h = tokio::spawn(async move {
        let ctx = task_ctx;
        let name = b.name.clone();
        let input = match file {
            Some((kind, file, name)) => Ok(Input::File { kind, file, name }),
            None => pg::pg_source(&ctx, &source)
                .await
                .map(Input::Pg)
                .map_err(unavailable),
        };
        let res = match input {
            Err(r) => Err(BuildErr::Before(r)),
            Ok(input) => tokio::task::spawn_blocking(move || refresh_build(b, input))
                .await
                .unwrap_or_else(|e| Err(BuildErr::After(join_err(e)))),
        };
        let why = end_build(guard, &name, res).err().map(|r| r.text);
        ctx.blind.set_build_error(&name, why);
    });
    ctx.blind.track_build(h);
    let mut a = Map::new();
    a.insert("started".into(), Value::Bool(true));
    Ok(Value::Object(a))
}

/// The snapshot from `input`, then the build (blocking).
fn refresh_build(b: BuildIn, input: Input) -> Result<Built, BuildErr> {
    let before = BuildErr::Before;
    // This build replaces any staged one: a later commit must not pair an
    // old `staged.json` with this stage.
    remove_entry(&b.dir.root.join(STAGED_FILE))
        .map_err(|e| before(unavailable(format!("could not clear {STAGED_FILE}: {e}"))))?;
    let (mut src, copy) = open_input(&b.dir, input).map_err(before)?;
    let (blind, name) = (Arc::clone(&b.ctx.blind), b.name.clone());
    let info = stage_snapshot(&b.dir, src.as_mut(), &mut |p| blind.progress(&name, p))
        .map_err(|e| shield_refusal(&e));
    drop(src);
    drop(copy);
    let info = info.map_err(before)?;
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
/// A dataset that is not there is not an error. Once the keys are being
/// shredded the dataset never shows `Live` again, whatever fails.
pub async fn rm(
    ctx: &Arc<Ctx>,
    peer: &PeerCred,
    args: &Map<String, Value>,
) -> Result<Value, Refusal> {
    let name = dataset_arg(args)?;
    let cfg = policy_dataset(ctx, &name).map(|p| p.0);
    if !may_manage(ctx, peer, &name, cfg.as_ref()).await {
        return Err(manage_refusal(&name));
    }
    let mut guard = BuildGuard::begin(&ctx.blind, &name)?;
    let dir = ctx.blind.dataset_dir(&name);
    let mut a = Map::new();
    if std::fs::symlink_metadata(&dir.root).is_err() {
        guard.done(DatasetState::Absent);
        a.insert("removed".into(), Value::Bool(false));
        return Ok(Value::Object(a));
    }
    let version = keys::load(ctx, &name).map_or(0, |k| k.version);
    let live = guard.previous_live().map(|p| p.1);
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
    // From here the old build is gone for asks, whatever fails (I1).
    guard.previous = Some(DatasetState::NeedsRefresh(format!(
        "{name} was being removed: saiife blind data rm --dataset {name}"
    )));
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
